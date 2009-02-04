#!/usr/bin/python
#
# 2008 Aleksei Gorny, mentored by Mike Perry

'''
Snakes on a Tor exit node scanner

The SoaT scanner checks whether exit nodes behave by initiating connections
to semi-randomly chosen targets using several protocols (http, https, ssh, smtp, imap, etc)
and comparing content received directly and via tor.

It interacts with metatroller and the control port to be aware of the tor network status.

To run SoaT: 
1) make sure you have py-openssl packages installed (see README)
2) open Tor control port in the torrc
3) start metatroller in the background (python ./metatroller.py)
4) start soat (python ./soat.py) with some testing flags (run it without any flags
    to see which options are available)
5) check the results later by running soatstats (python ./soatstats.py)

'''

__all__ = ["ExitNodeScanner", "DNSRebindScanner", "load_wordlist"]

import commands
import getopt
import os
import random
import re
from sets import Set
import smtplib
import socket
import sys
import time
import urllib
import urllib2
import traceback
import copy
import StringIO
import zlib,gzip
import urlparse
import cookielib
import sha
import Queue
import threading

from libsoat import *

sys.path.append("../")

from TorCtl import TorUtil, TorCtl, PathSupport
from TorCtl.TorUtil import meta_port, meta_host, control_port, control_host, tor_port, tor_host
from TorCtl.TorUtil import *
from TorCtl.PathSupport import *
from TorCtl.TorCtl import Connection, EventHandler

import OpenSSL
from OpenSSL import *

sys.path.append("./libs/")
# XXX: Try to determine if we should be using MinimalSoup
from BeautifulSoup.BeautifulSoup import BeautifulSoup, SoupStrainer, Tag
from SocksiPy import socks
import Pyssh.pyssh

from soat_config import *

search_cookies=None
linebreak = '\r\n'



# Oh yeah. so dirty. Blame this guy if you hate me:
# http://mail.python.org/pipermail/python-bugs-list/2008-October/061202.html
_origsocket = socket.socket
class BindingSocket(_origsocket):
  bind_to = None
  def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, _sock=None):
    _origsocket.__init__(self, family, type, proto, _sock)
    if BindingSocket.bind_to:
      plog("DEBUG", "Binding socket to "+BindingSocket.bind_to)
      self.bind((BindingSocket.bind_to, 0))
socket.socket = BindingSocket 


# Http request handling
def http_request(address, cookie_jar=None, headers=firefox_headers):
  ''' perform a http GET-request and return the content received '''
  request = urllib2.Request(address)
  for h in headers.iterkeys():
    request.add_header(h, headers[h])

  content = ""
  new_cookies = []
  mime_type = ""
  try:
    if cookie_jar != None:
      opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie_jar))
      reply = opener.open(request)
      if "__filename" in cookie_jar.__dict__:
        cookie_jar.save(cookie_jar.__filename)
      new_cookies = cookie_jar.make_cookies(reply, request)
    else:
      reply = urllib2.urlopen(request)

    length = reply.info().get("Content-Length")
    if length and int(length) > max_content_size:
      plog("WARN", "Max content size exceeded for "+address+": "+length)
      return (reply.code, [], "", "")
    mime_type = reply.info().type
    content = decompress_response_data(reply)
  except urllib2.HTTPError, e:
    plog('WARN', "HTTP Error during request of "+address)
    traceback.print_exc()
    return (e.code, [], "", "") 
  except (ValueError, urllib2.URLError):
    plog('WARN', 'The http-request address ' + address + ' is malformed')
    traceback.print_exc()
    return (0, [], "", "")
  except (IndexError, TypeError, socks.Socks5Error), e:
    plog('WARN', 'An error occured while negotiating socks5 with Tor: '+str(e))
    traceback.print_exc()
    return (0, [], "", "")
  except KeyboardInterrupt:
    raise KeyboardInterrupt
  except:
    plog('WARN', 'An unknown HTTP error occured for '+address)
    traceback.print_exc()
    return (0, [], "", "")

  # TODO: Consider also returning mime type here
  return (reply.code, new_cookies, mime_type, content)

class Test:
  """ Base class for our tests """
  def __init__(self, mt, proto, port):
    self.proto = proto
    self.port = port
    self.mt = mt
    self.datahandler = DataHandler()
    self.min_targets = 10
    self.marked_nodes = sets.Set([])

  def run_test(self): 
    raise NotImplemented()

  def get_targets(self): 
    raise NotImplemented()

  def get_node(self):
    return random.choice(self.nodes)

  def remove_target(self, target):
    if target in self.targets: self.targets.remove(target)
    if len(self.targets) < self.min_targets:
      plog("NOTICE", self.proto+" scanner short on targets. Adding more")
      self.targets.extend(self.get_targets())

  def update_nodes(self):
    self.nodes = self.mt.node_manager.get_nodes_for_port(self.port)
    self.node_map = {}
    for n in self.nodes: 
      self.node_map[n.idhex] = n
    self.total_nodes = len(self.nodes)
    self.all_nodes = sets.Set(self.nodes)

  def mark_chosen(self, node):
    self.nodes_marked += 1
    self.marked_nodes.add(node)
     
  def finished(self):
    return not self.marked_nodes ^ self.all_nodes

  def percent_complete(self):
    return round(100.0*self.nodes_marked/self.total_nodes, 1)
 
  def rewind(self):
    self.targets = self.get_targets()
    if not self.targets:
      raise NoURLsFound("No URLS found for protocol "+self.proto)
    if type(self.targets) == dict:
      for subtype in self.targets.iterkeys():
        targets = "\n\t".join(self.targets[subtype])
        plog("INFO", "Using the following urls for "+self.proto+"/"+subtype+" scan:\n\t"+targets) 
        
    else:
      targets = "\n\t".join(self.targets)
      plog("INFO", "Using the following urls for "+self.proto+" scan:\n\t"+targets) 
    self.tests_run = 0
    self.nodes_marked = 0
    self.marked_nodes = sets.Set([])

class SearchBasedTest(Test):
  def __init__(self, mt, proto, port, wordlist):
    self.wordlist = wordlist
    Test.__init__(self, mt, proto, port)

  def _is_useable_url(self, url, valid_schemes=None, filetypes=None):
    (scheme, netloc, path, params, query, fragment) = urlparse.urlparse(url)
    if netloc.rfind(":") != -1:
      # XXX: %-encoding?
      port = netloc[netloc.rfind(":")+1:]
      try:
        if int(port) != self.port:
          return False
      except:
        traceback.print_exc()
        plog("WARN", "Unparseable port "+port+" in "+url)
        return False
    if valid_schemes and scheme not in valid_schemes:
      return False
    if filetypes: # Must be checked last
      for filetype in filetypes:
        if url[-len(filetype):] == filetype:
          return True
      return False
    return True

  def get_search_urls(self, protocol='any', results_per_type=10, host_only=False, filetypes=['any'], search_mode=default_search_mode):
    ''' 
    construct a list of urls based on the wordlist, filetypes and protocol. 
    '''
    plog('INFO', 'Searching google for relevant sites...')
  
    urllist = []
    for filetype in filetypes:
      type_urls = []
  
      while len(type_urls) < results_per_type:
        query = random.choice(self.wordlist)
        if filetype != 'any':
          query += " "+search_mode["filetype"]+filetype
        if protocol != 'any' and search_mode["inurl"]:
          query += " "+search_mode["inurl"]+protocol # this isn't too reliable, but we'll re-filter results later
        #query += '&num=' + `g_results_per_page` 
  
        # search google for relevant pages
        # note: google only accepts requests from idenitified browsers
        # TODO gracefully handle the case when google doesn't want to give us result anymore
        host = search_mode["host"]
        params = urllib.urlencode({search_mode["query"] : query})
        search_path = '/search' + '?' + params
        search_url = "http://"+host+search_path
         
        plog("INFO", "Search url: "+search_url)
        try:
          # XXX: This does not handle http error codes.. (like 302!)
          if search_mode["useragent"]:
            (code, new_cookies, mime_type, content) = http_request(search_url, search_cookies)
          else:
            headers = copy.copy(firefox_headers)
            del headers["User-Agent"]
            (code, new_cookies, mime_type, content) = http_request(search_url, search_cookies, headers)[1]
        except socket.gaierror:
          plog('ERROR', 'Scraping of http://'+host+search_path+" failed")
          traceback.print_exc()
          return list(Set(urllist))
        except:
          plog('ERROR', 'Scraping of http://'+host+search_path+" failed")
          traceback.print_exc()
          # Bloody hack just to run some tests overnight
          return [protocol+"://www.eff.org", protocol+"://www.fastmail.fm", protocol+"://www.torproject.org", protocol+"://secure.wikileaks.org/"]
  
        links = SoupStrainer('a')
        try:
          soup = BeautifulSoup(content, parseOnlyThese=links)
        except Exception:
          plog('ERROR', 'Soup-scraping of http://'+host+search_path+" failed")
          traceback.print_exc()
          print "Content is: "+str(content)
          return [protocol+"://www.eff.org", protocol+"://www.fastmail.fm", protocol+"://www.torproject.org", protocol+"://secure.wikileaks.org/"]
        
        # get the links and do some additional filtering
        for link in soup.findAll('a', {'class' : search_mode["class"]}):
          url = link['href']
          if protocol == 'any': prot_list = None
          else: prot_list = [protocol]
          if filetype == 'any': file_list = None
          else: file_list = filetypes

          if self._is_useable_url(url, prot_list, file_list):
            if host_only:
              # XXX: %-encoding, @'s, etc?
              host = urlparse.urlparse(url)[1]
              type_urls.append(host)
            else:
              type_urls.append(url)
          else:
            pass
        plog("INFO", "Have "+str(len(type_urls))+"/"+str(results_per_type)+" google urls so far..") 

      # make sure we don't get more urls than needed
      # hrmm...
      #if type_urls > results_per_type:
      #  type_urls = random.sample(type_urls, results_per_type) 
      urllist.extend(type_urls)
       
    return list(Set(urllist))

class HTTPTest(SearchBasedTest):
  def __init__(self, mt, wordlist, filetypes=scan_filetypes):
    # FIXME: Handle http urls w/ non-80 ports..
    SearchBasedTest.__init__(self, mt, "HTTP", 80, wordlist)
    self.fetch_targets = 5
    self.httpcode_fails = {}
    self.exit_fails = {}
    self.successes = {}
    self.exit_limit = 100
    self.httpcode_limit = 100
    self.scan_filetypes = filetypes
    self.results = []

  def check_cookies(self):
    tor_cookies = "\n"
    plain_cookies = "\n"
    for cookie in self.tor_cookie_jar:
      tor_cookies += "\t"+cookie.name+":"+cookie.domain+cookie.path+" discard="+str(cookie.discard)+"\n"
    for cookie in self.cookie_jar:
      plain_cookies += "\t"+cookie.name+":"+cookie.domain+cookie.path+" discard="+str(cookie.discard)+"\n"
    if tor_cookies != plain_cookies:
      exit_node = self.mt.get_exit_node()
      plog("ERROR", "Cookie mismatch at "+exit_node+":\nTor Cookies:"+tor_cookies+"\nPlain Cookies:\n"+plain_cookies)
      result = CookieTestResult(exit_node, TEST_FAILURE, 
                            FAILURE_COOKIEMISMATCH, plain_cookies, 
                            tor_cookies)
      self.results.append(result)
      self.datahandler.saveResult(result)
      return TEST_FAILURE

    return TEST_SUCCESS

  def run_test(self):
    # A single test should have a single cookie jar
    self.tor_cookie_jar = cookielib.LWPCookieJar()
    self.cookie_jar = cookielib.LWPCookieJar()
    # XXX: Change these headers (esp accept) based on 
    # url type
    self.headers = copy.copy(firefox_headers)
    
    ret_result = TEST_SUCCESS
    self.tests_run += 1

    n_tests = random.choice(xrange(1,len(self.scan_filetypes)+1))
    filetypes = random.sample(self.scan_filetypes, n_tests)
    
    plog("INFO", "HTTPTest decided to fetch "+str(n_tests)+" urls of types: "+str(filetypes))

    for ftype in filetypes:
      # XXX: Set referrer to random or none for each of these
      address = random.choice(self.targets[ftype])
      result = self.check_http(address)
      if result > ret_result:
        ret_result = result
    result = self.check_cookies()
    if result > ret_result:
      ret_result = result
    return ret_result

  def get_targets(self):
    raw_urls = self.get_search_urls('http', self.fetch_targets, filetypes=self.scan_filetypes)

    urls = {} 
    # Slow, but meh..
    for ftype in self.scan_filetypes: urls[ftype] = []
    for url in raw_urls:
      for ftype in self.scan_filetypes:
        if url[-len(ftype):] == ftype:
          urls[ftype].append(url)
    return urls     
 
  def remove_target(self, address):
    SearchBasedTest.remove_target(self, address)
    if address in self.httpcode_fails: del self.httpcode_fails[address]
    if address in self.successes: del self.successes[address]
    if address in self.exit_fails: del self.exit_fails[address]
    kill_results = []
    for r in self.results:
      if r.site == address:
        kill_results.append(r)
    for r in kill_results:
      # XXX: Move files instead of removing them..
      #r.remove_files()
      self.results.remove(r)
    
  def register_exit_failure(self, address, exit_node):
    if address in self.exit_fails:
      self.exit_fails[address].add(exit_node)
    else:
      self.exit_fails[address] = sets.Set([exit_node])

    # TODO: Do something if abundance of succesful tests?
    # Problem is this can still trigger for localized content
    err_cnt = len(self.exit_fails[address])
    if err_cnt > self.exit_limit:
      if address not in self.successes: self.successes[address] = 0
      plog("NOTICE", "Excessive HTTP 2-way failure ("+str(err_cnt)+" vs "+str(self.successes[address])+") for "+address+". Removing.")
  
      self.remove_target(address)
    else:
      plog("ERROR", self.proto+" 2-way failure at "+exit_node+". This makes "+str(err_cnt)+" node failures for "+address)

  def register_httpcode_failure(self, address, exit_node):
    if address in self.httpcode_fails:
      self.httpcode_fails[address].add(exit_node)
    else:
      self.httpcode_fails[address] = sets.Set([exit_node])
    
    err_cnt = len(self.httpcode_fails[address])
    if err_cnt > self.httpcode_limit:
      # Remove all associated data for this url.
      # (Note, this also seems to imply we should report BadExit in bulk,
      # after we've had a chance for these false positives to be weeded out)
      if address not in self.successes: self.successes[address] = 0
      plog("NOTICE", "Excessive HTTP error code failure ("+str(err_cnt)+" vs "+str(self.successes[address])+") for "+address+". Removing.")

      self.remove_target(address)
    else:
      plog("ERROR", self.proto+" http error code failure at "+exit_node+". This makes "+str(err_cnt)+" node failures for "+address)
    

  def check_http_nodynamic(self, address):
    ''' check whether a http connection to a given address is molested '''
    plog('INFO', 'Conducting an http test with destination ' + address)


    # an address representation acceptable for a filename 
    address_file = self.datahandler.safeFilename(address[7:])
    content_prefix = http_content_dir+address_file
    failed_prefix = http_failed_dir+address_file
    
    # Keep a copy of the cookie jar before mods for refetch
    orig_cookie_jar = cookielib.LWPCookieJar()
    for cookie in self.cookie_jar: orig_cookie_jar.set_cookie(cookie)

    try:
      # Load content from disk, md5
      content_file = open(content_prefix+'.content', 'r')
      sha1sum = sha.sha()
      buf = content_file.read(4096)
      while buf:
        sha1sum.update(buf)
        buf = content_file.read(4096)
      content_file.close()
      self.cookie_jar.load(content_prefix+'.cookies')
      content = None 

    except IOError:
      (code, new_cookies, mime_type, content) = http_request(address, self.cookie_jar, self.headers)

      if code - (code % 100) != 200:
        plog("NOTICE", "Non-tor HTTP error "+str(code)+" fetching content for "+address)
        # Just remove it
        self.remove_target(address)
        return TEST_INCONCLUSIVE

      if not content:
        plog("WARN", "Failed to direct load "+address)
        return TEST_INCONCLUSIVE 
      sha1sum = sha.sha(content)

      content_file = open(content_prefix+'.content', 'w')
      content_file.write(content)
      content_file.close()
      
      # Need to do set subtraction and only save new cookies.. 
      # or extract/make_cookies
      new_cookie_jar = cookielib.LWPCookieJar()
      for cookie in new_cookies: new_cookie_jar.set_cookie(cookie)
      try:
        new_cookie_jar.save(content_prefix+'.cookies')
      except:
        traceback.print_exc()
        plog("WARN", "Error saving cookies in "+str(self.cookie_jar)+" to "+content_prefix+".cookies")

    except TypeError, e:
      plog('ERROR', 'Failed obtaining the shasum for ' + address)
      plog('ERROR', e)
      return TEST_INCONCLUSIVE


    defaultsocket = socket.socket
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
    socket.socket = socks.socksocket

    (pcode, pnew_cookies, pmime_type, pcontent) = http_request(address, self.tor_cookie_jar, self.headers)
    psha1sum = sha.sha(pcontent)

    # reset the connection to direct
    socket.socket = defaultsocket

    exit_node = self.mt.get_exit_node()
    if exit_node == 0 or exit_node == '0' or not exit_node:
      plog('WARN', 'We had no exit node to test, skipping to the next test.')
      return TEST_SUCCESS

    if pcode - (pcode % 100) != 200:
      plog("NOTICE", exit_node+" had error "+str(pcode)+" fetching content for "+address)
      result = HttpTestResult(exit_node, address, TEST_INCONCLUSIVE,
                              INCONCLUSIVE_BADHTTPCODE+str(pcode))
      self.results.append(result)
      self.datahandler.saveResult(result)
      self.register_httpcode_failure(address, exit_node)
      return TEST_INCONCLUSIVE

    # if we have no content, we had a connection error
    if pcontent == "":
      plog("NOTICE", exit_node+" failed to fetch content for "+address)
      result = HttpTestResult(exit_node, address, TEST_INCONCLUSIVE,
                              INCONCLUSIVE_NOEXITCONTENT)
      self.results.append(result)
      self.datahandler.saveResult(result)
      return TEST_INCONCLUSIVE

    # compare the content
    # if content matches, everything is ok
    if psha1sum.hexdigest() == sha1sum.hexdigest():
      result = HttpTestResult(exit_node, address, TEST_SUCCESS)
      self.results.append(result)
      #self.datahandler.saveResult(result)
      if address in self.successes: self.successes[address]+=1
      else: self.successes[address]=1
      return TEST_SUCCESS

    # if content doesnt match, update the direct content and use new cookies
    # If we have alternate IPs to bind to on this box, use them?
    # Sometimes pages have the client IP encoded in them..
    BindingSocket.bind_to = refetch_ip
    (code_new, new_cookies_new, mime_type_new, content_new) = http_request(address, orig_cookie_jar, self.headers)
    BindingSocket.bind_to = None
    
    if not content_new:
      plog("WARN", "Failed to re-frech "+address+" outside of Tor. Did our network fail?")
      result = HttpTestResult(exit_node, address, TEST_INCONCLUSIVE, 
                              INCONCLUSIVE_NOLOCALCONTENT)
      self.results.append(result)
      self.datahandler.saveResult(result)
      return TEST_INCONCLUSIVE

    sha1sum_new = sha.sha(content_new)

    # compare the new and old content
    # if they match, means the node has been changing the content
    if sha1sum.hexdigest() == sha1sum_new.hexdigest():
      # XXX: Check for existence of this file before overwriting
      exit_content_file = open(failed_prefix+'.content.'+exit_node[1:], 'w')
      exit_content_file.write(pcontent)
      exit_content_file.close()

      result = HttpTestResult(exit_node, address, TEST_FAILURE, 
                              FAILURE_EXITONLY, sha1sum.hexdigest(), 
                              psha1sum.hexdigest(), content_prefix+".content",
                              exit_content_file.name)
      self.results.append(result)
      self.datahandler.saveResult(result)

      self.register_exit_failure(address, exit_node)
      return TEST_FAILURE

    # if content has changed outside of tor, update the saved file
    os.rename(content_prefix+'.content', content_prefix+'.content-old')
    new_content_file = open(content_prefix+'.content', 'w')
    new_content_file.write(content_new)
    new_content_file.close()

    # Need to do set subtraction and only save new cookies.. 
    # or extract/make_cookies
    new_cookie_jar = cookielib.LWPCookieJar()
    for cookie in new_cookies_new: new_cookie_jar.set_cookie(cookie)
    os.rename(content_prefix+'.cookies', content_prefix+'.cookies-old')
    try:
      new_cookie_jar.save(content_prefix+'.cookies')
    except:
      traceback.print_exc()
      plog("WARN", "Error saving cookies in "+str(new_cookie_jar)+" to "+content_prefix+".cookies")

    # compare the node content and the new content
    # if it matches, everything is ok
    if psha1sum.hexdigest() == sha1sum_new.hexdigest():
      result = HttpTestResult(exit_node, address, TEST_SUCCESS)
      self.results.append(result)
      #self.datahandler.saveResult(result)
      if address in self.successes: self.successes[address]+=1
      else: self.successes[address]=1
      return TEST_SUCCESS
 
    if not content:
      content_file = open(content_prefix+'.content', 'r')
      content = content_file.read()
      content_file.close()

    # Dirty dirty dirty...
    return (pcontent, psha1sum, content, sha1sum, content_new, sha1sum_new,
            exit_node)

  def check_http(self, address):
    ret = self.check_http_nodynamic(address)
    if type(ret) == int:
      return ret
   
    (pcontent, psha1sum, content, sha1sum, content_new, sha1sum_new, exit_node) = ret
     
    address_file = self.datahandler.safeFilename(address[7:])
    content_prefix = http_content_dir+address_file
    failed_prefix = http_failed_dir+address_file

    # XXX: Check for existence of this file before overwriting
    exit_content_file = open(failed_prefix+'.dyn-content.'+exit_node[1:], 'w')
    exit_content_file.write(pcontent)
    exit_content_file.close()

    result = HttpTestResult(exit_node, address, TEST_FAILURE, 
                            FAILURE_DYNAMICBINARY, sha1sum_new.hexdigest(), 
                            psha1sum.hexdigest(), content_prefix+".content",
                            exit_content_file.name, 
                            content_prefix+'.content-old',
                            sha1sum.hexdigest())
    self.results.append(result)
    self.datahandler.saveResult(result)

    # The HTTP Test should remove address immediately.
    plog("WARN", "HTTP Test is removing dynamic URL "+address)
    self.remove_target(address)
    return TEST_FAILURE

class HTMLTest(HTTPTest):
  def __init__(self, mt, wordlist, recurse_filetypes=scan_filetypes):
    # XXX: Change these to 10 and 20 once we exercise the fetch logic
    HTTPTest.__init__(self, mt, wordlist, recurse_filetypes)
    self.proto = "HTML"
    self.min_targets = 9
    self.recurse_filetypes = recurse_filetypes
    self.fetch_queue = Queue.Queue()
    self.dynamic_fails = {}
    self.dynamic_limit = 10
 
  def run_test(self):
    # A single test should have a single cookie jar
    self.tor_cookie_jar = cookielib.LWPCookieJar()
    self.cookie_jar = cookielib.LWPCookieJar()
    # XXX: Change these headers (esp accept) based on 
    # url type
    self.headers = copy.copy(firefox_headers)
    
    ret_result = TEST_SUCCESS
    self.tests_run += 1
    # XXX: Set referrer to address for subsequent fetches
    # XXX: Set referrer to random or none for initial fetch
    # XXX: Watch for spider-traps! (ie mutually sourcing iframes)
    # Keep a trail log for this test and check for loops
    address = random.choice(self.targets)

    self.fetch_queue.put_nowait(("html", address))
    while not self.fetch_queue.empty():
      (test, url) = self.fetch_queue.get_nowait()
      if test == "html": result = self.check_html(url)
      elif test == "http": result = self.check_http(url)
      elif test == "js": result = self.check_js(url)
      else: 
        plog("WARN", "Unknown test type: "+test+" for "+url)
        result = TEST_SUCCESS
      if result > ret_result:
		ret_result = result
    result = self.check_cookies()
    if result > ret_result:
      ret_result = result
    return ret_result

  def get_targets(self):
    return self.get_search_urls('http', self.fetch_targets) 

  def remove_target(self, address):
    HTTPTest.remove_target(self, address)
    if address in self.dynamic_fails: del self.dynamic_fails[address]

  def register_dynamic_failure(self, address, exit_node):
    if address in self.dynamic_fails:
      self.dynamic_fails[address].add(exit_node)
    else:
      self.dynamic_fails[address] = sets.Set([exit_node])
    
    err_cnt = len(self.dynamic_fails[address])
    if err_cnt > self.dynamic_limit:
      # Remove all associated data for this url.
      # (Note, this also seems to imply we should report BadExit in bulk,
      # after we've had a chance for these false positives to be weeded out)
      if address not in self.successes: self.successes[address] = 0
      plog("NOTICE", "Excessive HTTP 3-way failure ("+str(err_cnt)+" vs "+str(self.successes[address])+") for "+address+". Removing.")

      self.remove_target(address)
    else:
      plog("ERROR", self.proto+" 3-way failure at "+exit_node+". This makes "+str(err_cnt)+" node failures for "+address)

  def _add_recursive_targets(self, soup, orig_addr):
    # Only pull at most one filetype from the list of 'a' links
    targets = []
    got_type = {}
    # Hrmm, if we recursively strained only these tags, this might be faster
    for tag in tags_to_recurse:
      tags = soup.findAll(tag)
      for t in tags:
        #plog("DEBUG", "Got tag: "+str(t))
        for a in t.attrs:
          attr_name = a[0]
          attr_tgt = a[1]
          if attr_name in attrs_to_recurse:
            if t.name in recurse_html:
              targets.append(("html", urlparse.urljoin(orig_addr, attr_tgt)))
            elif t.name in recurse_script:
              if t.name == "link":
                for a in t.attrs:
                  if a[0] == "type" and a[1] in link_script_types:
                    targets.append(("js", urlparse.urljoin(orig_addr, attr_tgt)))
              else:
                targets.append(("js", urlparse.urljoin(orig_addr, attr_tgt)))
            elif t.name == 'a':
              if attr_name == "href":
                for f in self.recurse_filetypes:
                  if f not in got_type and attr_tgt[-len(f):] == f:
                    got_type[f] = 1
                    targets.append(("http", urlparse.urljoin(orig_addr, attr_tgt)))
            else:
              targets.append(("http", urlparse.urljoin(orig_addr, attr_tgt)))
    for i in sets.Set(targets):
      if self._is_useable_url(i[1], html_schemes):
        plog("NOTICE", "Adding "+i[0]+" target: "+i[1])
        self.fetch_queue.put_nowait(i)
      else:
        plog("NOTICE", "Skipping "+i[0]+" target: "+i[1])


  def _tag_not_worthy(self, tag):
    if tag.name in tags_to_check:
      return False
    for attr in tag.attrs:
      if attr[0] in attrs_to_check_map:
        return False
    return True
 
  def _recursive_strain(self, soup):
    """ Remove all tags that are of no interest. Also remove content """
    to_extract = []
    for tag in soup.findAll():
      to_prune = []
      for attr in tag.attrs:
        if attr[0] in attrs_to_prune:
          to_prune.append(attr)
      for attr in to_prune:
        tag.attrs.remove(attr)
      if self._tag_not_worthy(tag):
        to_extract.append(tag)
      if tag.name not in tags_preserve_inner:
        for child in tag.childGenerator():
          if not isinstance(child, Tag) or self._tag_not_worthy(child):
            to_extract.append(child)
    for tag in to_extract:
      if isinstance(tag, Tag):
        parent = tag.findParent()
        for child in tag.findChildren():
          parent.append(child)
    for tag in to_extract:
      tag.extract()
    return soup      

  def check_js(self, address):
    plog('INFO', 'Conducting a js test with destination ' + address)
    ret = self.check_http_nodynamic(address)
    
    if type(ret) == int:
      return ret
    (tor_js, tsha, orig_js, osha, new_js, nsha, exit_node) = ret

    jsdiff = JSDiffer(orig_js)
    jsdiff.prune_differences(new_js)
    false_positive = not jsdiff.contains_differences(tor_js)

    if false_positive:
      result = JsTestResult(exit_node, address, TEST_SUCCESS)
      self.results.append(result)
      #self.datahandler.saveResult(result)
      if address in self.successes: self.successes[address]+=1
      else: self.successes[address]=1
      return TEST_SUCCESS
    else:
      address_file = self.datahandler.safeFilename(address[7:])
      content_prefix = http_content_dir+address_file
      failed_prefix = http_failed_dir+address_file

      # XXX: Check for existence of this file before overwriting
      exit_content_file = open(failed_prefix+'.dyn-content.'+exit_node[1:], 'w')
      exit_content_file.write(tor_js)
      exit_content_file.close()

      result = JsTestResult(exit_node, address, TEST_FAILURE, 
                              FAILURE_DYNAMICJS, content_prefix+".content",
                              exit_content_file.name, 
                              content_prefix+'.content-old')
      self.results.append(result)
      self.datahandler.saveResult(result)
      plog("ERROR", "Javascript 3-way failure at "+exit_node+" for "+address)

      return TEST_FAILURE

  def check_html_notags(self, address):
    plog('INFO', 'Conducting a html tagless test with destination ' + address)
    ret = self.check_http_nodynamic(address)
    
    if type(ret) == int:
      return ret
    (tor_js, tsha, orig_js, osha, new_js, nsha, exit_node) = ret
    pass

  def check_html(self, address):
    # TODO: Break this out into a check_html_notags that just does a sha check
    # FIXME: Also check+store non-tor mime types
    ''' check whether a http connection to a given address is molested '''
    plog('INFO', 'Conducting an html test with destination ' + address)

    # an address representation acceptable for a filename 
    address_file = self.datahandler.safeFilename(address[7:])
    content_prefix = http_content_dir+address_file
    failed_prefix = http_failed_dir+address_file

    # Keep a copy of the cookie jar before mods for refetch
    orig_cookie_jar = cookielib.LWPCookieJar()
    for cookie in self.cookie_jar: orig_cookie_jar.set_cookie(cookie)

    elements = SoupStrainer(lambda name, attrs: name in tags_to_check or 
        len(Set(map(lambda a: a[0], attrs)).intersection(Set(attrs_to_check))) > 0)

    # load the original tag structure
    # if we don't have any yet, get it
    soup = 0
    try:
      tag_file = open(content_prefix+'.tags', 'r')
      soup = BeautifulSoup(tag_file.read())
      tag_file.close()
      
      self.cookie_jar.load(content_prefix+'.cookies', 'w')

    except IOError:
      (code, new_cookies, mime_type, content) = http_request(address, self.cookie_jar, self.headers)

      if code - (code % 100) != 200:
        plog("NOTICE", "Non-tor HTTP error "+str(code)+" fetching content for "+address)
        # Just remove it
        self.remove_target(address)
        return TEST_INCONCLUSIVE

      content = content.decode('ascii','ignore')
      soup = self._recursive_strain(BeautifulSoup(content, parseOnlyThese=elements))

      # XXX: str of this may be bad if there are unicode chars inside
      string_soup = str(soup)
      if not string_soup:
        plog("WARN", "Empty soup for "+address)
      tag_file = open(content_prefix+'.tags', 'w')
      tag_file.write(string_soup) 
      tag_file.close()

      # Need to do set subtraction and only save new cookies.. 
      # or extract/make_cookies
      new_cookie_jar = cookielib.LWPCookieJar()
      for cookie in new_cookies: new_cookie_jar.set_cookie(cookie)
      try:
        new_cookie_jar.save(content_prefix+'.cookies')
      except:
        traceback.print_exc()
        plog("WARN", "Error saving cookies in "+str(new_cookie_jar)+" to "+content_prefix+".cookies")

      content_file = open(content_prefix+'.content', 'w')
      content_file.write(content)
      content_file.close()

    except TypeError, e:
      plog('ERROR', 'Failed parsing the tag tree for ' + address)
      plog('ERROR', e)
      return TEST_INCONCLUSIVE

    if soup == 0:
      plog('ERROR', 'Failed to get the correct tag structure for ' + address)
      return TEST_INCONCLUSIVE


    defaultsocket = socket.socket
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
    socket.socket = socks.socksocket

    # Wikipedia and others can give us 403.. So what do we do about that?
    # Count the number of occurrances vs successful runs then remove the url
    (pcode, pcookies, pmime_type, pcontent) = http_request(address, self.tor_cookie_jar, self.headers)

    # reset the connection to direct
    socket.socket = defaultsocket

    exit_node = self.mt.get_exit_node()
    if exit_node == 0 or exit_node == '0' or not exit_node:
      plog('WARN', 'We had no exit node to test, skipping to the next test.')
      return TEST_SUCCESS

    if pcode - (pcode % 100) != 200:
      plog("NOTICE", exit_node+" had error "+str(pcode)+" fetching content for "+address)
      result = HttpTestResult(exit_node, address, TEST_INCONCLUSIVE,
                              INCONCLUSIVE_BADHTTPCODE+str(pcode))
      self.results.append(result)
      self.datahandler.saveResult(result)
      self.register_httpcode_failure(address, exit_node)
      return TEST_INCONCLUSIVE

    # if we have no content, we had a connection error
    if pcontent == "":
      plog("NOTICE", exit_node+" failed to fetch content for "+address)
      result = HtmlTestResult(exit_node, address, TEST_INCONCLUSIVE,
                              INCONCLUSIVE_NOEXITCONTENT)
      self.results.append(result)
      self.datahandler.saveResult(result)
      return TEST_INCONCLUSIVE

    pcontent = pcontent.decode('ascii', 'ignore')
    psoup = self._recursive_strain(BeautifulSoup(pcontent, parseOnlyThese=elements))

    # Also find recursive urls
    recurse_elements = SoupStrainer(lambda name, attrs: 
         name in tags_to_recurse and 
            len(Set(map(lambda a: a[0], attrs)).intersection(Set(attrs_to_recurse))) > 0)
    self._add_recursive_targets(BeautifulSoup(pcontent, recurse_elements), 
                               address) 

    # compare the content
    # if content matches, everything is ok
    if str(psoup) == str(soup):
      result = HtmlTestResult(exit_node, address, TEST_SUCCESS)
      self.results.append(result)
      #self.datahandler.saveResult(result)
      if address in self.successes: self.successes[address]+=1
      else: self.successes[address]=1
      return TEST_SUCCESS

    # if content doesnt match, update the direct content and use new cookies
    # If we have alternate IPs to bind to on this box, use them?
    # Sometimes pages have the client IP encoded in them..
    BindingSocket.bind_to = refetch_ip
    (code_new, new_cookies_new, mime_type_new, content_new) = http_request(address, orig_cookie_jar, self.headers)
    BindingSocket.bind_to = None

    content_new = content_new.decode('ascii', 'ignore')
    if not content_new:
      plog("WARN", "Failed to re-frech "+address+" outside of Tor. Did our network fail?")
      result = HtmlTestResult(exit_node, address, TEST_INCONCLUSIVE, 
                              INCONCLUSIVE_NOLOCALCONTENT)
      self.results.append(result)
      self.datahandler.saveResult(result)
      return TEST_INCONCLUSIVE

    soup_new = self._recursive_strain(BeautifulSoup(content_new,
                                     parseOnlyThese=elements))
    # compare the new and old content
    # if they match, means the node has been changing the content
    if str(soup) == str(soup_new):
      # XXX: Check for existence of this file before overwriting
      exit_tag_file = open(failed_prefix+'.tags.'+exit_node[1:],'w')
      exit_tag_file.write(str(psoup))
      exit_tag_file.close()

      exit_content_file = open(failed_prefix+'.content.'+exit_node[1:], 'w')
      exit_content_file.write(pcontent)
      exit_content_file.close()

      result = HtmlTestResult(exit_node, address, TEST_FAILURE, 
                              FAILURE_EXITONLY, tag_file.name, 
                              exit_tag_file.name, content_prefix+".content",
                              exit_content_file.name)
      self.results.append(result)
      self.datahandler.saveResult(result)
 
      self.register_exit_failure(address, exit_node)
      return TEST_FAILURE

    # if content has changed outside of tor, update the saved file
    os.rename(content_prefix+'.tags', content_prefix+'.tags-old')
    string_soup_new = str(soup_new)
    if not string_soup_new:
      plog("WARN", "Empty soup for "+address)
    tag_file = open(content_prefix+'.tags', 'w')
    tag_file.write(string_soup_new) 
    tag_file.close()
      
    os.rename(content_prefix+'.cookies', content_prefix+'.cookies-old')
    # Need to do set subtraction and only save new cookies.. 
    # or extract/make_cookies
    new_cookie_jar = cookielib.LWPCookieJar()
    for cookie in new_cookies_new: new_cookie_jar.set_cookie(cookie)
    try:
      new_cookie_jar.save(content_prefix+'.cookies')
    except:
      traceback.print_exc()
      plog("WARN", "Error saving cookies in "+str(new_cookie_jar)+" to "+content_prefix+".cookies")

    os.rename(content_prefix+'.content', content_prefix+'.content-old')
    new_content_file = open(content_prefix+'.content', 'w')
    new_content_file.write(content_new)
    new_content_file.close()

    # compare the node content and the new content
    # if it matches, everything is ok
    if str(psoup) == str(soup_new):
      result = HtmlTestResult(exit_node, address, TEST_SUCCESS)
      self.results.append(result)
      #self.datahandler.saveResult(result)
      if address in self.successes: self.successes[address]+=1
      else: self.successes[address]=1
      return TEST_SUCCESS

    # Lets try getting just the tag differences
    # 1. Take difference between old and new tags both ways
    # 2. Make map of tags that change to their attributes
    # 3. Compare list of changed tags for tor vs new and
    #    see if any extra tags changed or if new attributes
    #    were added to additional tags
    old_vs_new = SoupDiffer(soup, soup_new)
    new_vs_old = SoupDiffer(soup_new, soup)
    new_vs_tor = SoupDiffer(soup_new, psoup)

    # I'm an evil man and I'm going to CPU hell..
    changed_tags = old_vs_new.changed_tags_with_attrs()
    changed_tags.update(new_vs_old.changed_tags_with_attrs())

    changed_attributes = old_vs_new.changed_attributes_by_tag()
    changed_attributes.update(new_vs_old.changed_attributes_by_tag())

    changed_content = bool(old_vs_new.changed_content() or old_vs_new.changed_content())
 
    # Verify all of our changed tags are present here 
    if new_vs_tor.has_more_changed_tags(changed_tags) or \
      new_vs_tor.has_more_changed_attrs(changed_attributes) or \
      new_vs_tor.changed_content() and not changed_content:
      false_positive = False
    else:
      false_positive = True

    if false_positive:
      jsdiff = JSSoupDiffer(soup)
      jsdiff.prune_differences(soup_new)
      false_positive = not jsdiff.contains_differences(psoup)

    if false_positive:
      plog("NOTICE", "False positive detected for dynamic change at "+address+" via "+exit_node)
      result = HtmlTestResult(exit_node, address, TEST_SUCCESS)
      self.results.append(result)
      #self.datahandler.saveResult(result)
      if address in self.successes: self.successes[address]+=1
      else: self.successes[address]=1
      return TEST_SUCCESS

    # XXX: Check for existence of this file before overwriting
    exit_tag_file = open(failed_prefix+'.dyn-tags.'+exit_node[1:],'w')
    exit_tag_file.write(str(psoup))
    exit_tag_file.close()

    exit_content_file = open(failed_prefix+'.dyn-content.'+exit_node[1:], 'w')
    exit_content_file.write(pcontent)
    exit_content_file.close()

    result = HtmlTestResult(exit_node, address, TEST_FAILURE, 
                            FAILURE_DYNAMICTAGS, tag_file.name, 
                            exit_tag_file.name, new_content_file.name,
                            exit_content_file.name, 
                            content_prefix+'.content-old',
                            content_prefix+'.tags-old')
    self.results.append(result)
    self.datahandler.saveResult(result)

    self.register_dynamic_failure(address, exit_node)
    return TEST_FAILURE
    

class SSLTest(SearchBasedTest):
  def __init__(self, mt, wordlist):
    self.test_hosts = 10
    SearchBasedTest.__init__(self, mt, "SSL", 443, wordlist)

  def run_test(self):
    self.tests_run += 1
    return self.check_openssl(random.choice(self.targets))

  def get_targets(self):
    return self.get_search_urls('https', self.test_hosts, True, search_mode=google_search_mode) 

  def ssl_request(self, address):
    ''' initiate an ssl connection and return the server certificate '''
    address=str(address) # Unicode hostnames not supported..
     
    # specify the context
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.set_verify_depth(1)

    # ready the certificate request
    request = crypto.X509Req()

    # open an ssl connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c = SSL.Connection(ctx, s)
    c.set_connect_state()
     
    try:
      c.connect((address, 443))
      c.send(crypto.dump_certificate_request(crypto.FILETYPE_PEM,request))
    except socket.error, e:
      plog('WARN','An error occured while opening an ssl connection to ' + address)
      plog('WARN', e)
      return 0
    except (IndexError, TypeError):
      plog('WARN', 'An error occured while negotiating socks5 with Tor (timeout?)')
      return 0
    except KeyboardInterrupt:
      raise KeyboardInterrupt
    except:
      plog('WARN', 'An unknown SSL error occured for '+address)
      traceback.print_exc()
      return 0
    
    # return the cert
    return c.get_peer_certificate()

  def check_openssl(self, address):
    ''' check whether an https connection to a given address is molested '''
    plog('INFO', 'Conducting an ssl test with destination ' + address)

    # an address representation acceptable for a filename 
    address_file = self.datahandler.safeFilename(address[8:])

    # get the cert via tor

    defaultsocket = socket.socket
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
    socket.socket = socks.socksocket

    cert = self.ssl_request(address)

    # reset the connection method back to direct
    socket.socket = defaultsocket

    exit_node = self.mt.get_exit_node()
    if exit_node == 0 or exit_node == '0' or not exit_node:
      plog('WARN', 'We had no exit node to test, skipping to the next test.')
      return TEST_FAILURE

    # if we got no cert, there was an ssl error
    if cert == 0:
      result = SSLTestResult(exit_node, address, 0, TEST_INCONCLUSIVE)
      self.datahandler.saveResult(result)
      return TEST_INCONCLUSIVE

    # load the original cert and compare
    # if we don't have the original cert yet, get it
    original_cert = 0
    try:
      cert_file = open(ssl_certs_dir + address_file + '.pem', 'r')
      cert_string = cert_file.read()
      original_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_string)
    except IOError:
      plog('INFO', 'Opening a direct ssl connection to ' + address)
      original_cert = self.ssl_request(address)
      if not original_cert:
        plog('WARN', 'Error getting the correct cert for ' + address)
        return TEST_INCONCLUSIVE
      if original_cert.has_expired():
        plog('WARN', 'The ssl cert for '+address+' seems to have expired. Skipping to the next test...')
        return TEST_INCONCLUSIVE
      cert_file = open(ssl_certs_dir + address_file + '.pem', 'w')
      cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, original_cert))
      cert_file.close()
    except OpenSSL.crypto.Error:
      plog('NOTICE', 'There are non-related files in ' + ssl_certs_dir + '. You should probably clean it.')
      return TEST_INCONCLUSIVE
    if not original_cert:
      plog('WARN', 'Error getting the correct cert for ' + address)
      return TEST_INCONCLUSIVE

    # get an easily comparable representation of the certs
    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    original_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, original_cert)

    # if certs match, everything is ok
    if cert_pem == original_cert_pem:
      cert_file = ssl_certs_dir + address_file + '.pem'
      result = SSLTestResult(exit_node, address, cert_file, TEST_SUCCESS)
      self.datahandler.saveResult(result)
      return TEST_SUCCESS
    
    # if certs dont match, open up a direct connection and update the cert
    plog('INFO', 'Opening a direct ssl connection to ' + address)
    original_cert_new = self.ssl_request(address)
    if original_cert_new == 0:
      plog('WARN', 'Error getting the correct cert for ' + address)
      result = SSLTestResult(exit_node, address, 0, TEST_INCONCLUSIVE)
      self.datahandler.saveResult(result)
      return TEST_INCONCLUSIVE

    original_cert_new_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, original_cert_new)

    # compare the old and new cert
    # if certs match, means the exit node has been messing with the cert
    if original_cert_pem == original_cert_new_pem:
      plog('ERROR', 'Exit node ' + exit_node + ' seems to be meddling with certificates. (' + address + ')')

      cert_file_name = ssl_certs_dir + address_file + '_' + exit_node[1:] + '.pem'
      cert_file = open(cert_file_name, 'w')
      cert_file.write(cert_pem)
      cert_file.close()

      result = SSLTestResult(exit_node, address, cert_file_name, TEST_FAILURE)
      self.datahandler.saveResult(result)
      return TEST_FAILURE

    # if comparsion fails, replace the old cert with the new one
    # XXX: Hrmm, probably should store as a seperate IP file in this case
    # so we don't keep alternating on sites that have round robin
    # DNS and different certs for each IP.. 
    cert_file = open(ssl_certs_dir + address_file + '.pem', 'w')
    cert_file.write(original_cert_new_pem)
    cert_file.close()
      
    # compare the new cert and the node cert
    # if certs match, everything is ok
    if cert_pem == original_cert_new_pem:
      cert_file = ssl_certs_dir + address_file + '.pem'
      result = SSLTestResult(exit_node, address, cert_file, TEST_SUCCESS)
      self.datahandler.saveResult(result)
      return TEST_SUCCESS

    # if certs dont match, means the exit node has been messing with the cert
    plog('ERROR', 'Exit node ' + exit_node + ' seems to be meddling with certificates. (' + address + ')')

    cert_file_name = ssl_certs_dir + address + '_' + exit_node[1:] + '.pem'
    cert_file = open(cert_file_name, 'w')
    cert_file.write(cert_pem)
    cert_file.close()

    result = SSLTestResult(exit_node, address, cert_file_name, TEST_FAILURE)
    self.datahandler.saveResult(result)

    return TEST_FAILURE

class POP3STest(Test):
  def __init__(self, mt):
    Test.__init__(self, mt, "POP3S", 110)

  def run_test(self):
    self.tests_run += 1
    return self.check_pop(random.choice(self.targets))

  def get_targets(self):
    return [] # XXX

  def check_pop(self, address, port=''):
    ''' 
    check whether a pop + tls connection to a given address is molested 
    it is implied that the server reads/sends messages compliant with RFC1939 & RFC2449
    '''

    plog('INFO', 'Conducting a pop test with destination ' + address)

    if not port:
      port = 110

    defaultsocket = socket.socket
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
    socket.socket = socks.socksocket

    capabilities_ok = False
    starttls_present = False
    tls_started = None
    tls_succeeded = None

    try:
      pop = Client(address, port)
    
      # read the server greeting
      server_greeting = pop.readline()

      # get the server capabilities
      pop.writeline('CAPA')
      capabilities = ''
      while 1:
        curr = pop.readline()
        if '+OK' in curr:
          capabilities_ok = True
        elif curr == '.':
          break
        elif 'STLS' in curr:
          starttls_present = True
      
      if not capabilities_ok:
        return TEST_INCONCLUSIVE

      # try to start tls negotiation
      if starttls_present:
        pop.writeline('STLS')

      starttls_response = pop.readline()
      starttls_started = '+OK' in starttls_response

      # negotiate TLS and issue some request to feel good about it
      # TODO check certs? 
      ctx = SSL.Context(SSL.SSLv23_METHOD)
      c = SSL.Connection(ctx, pop.sock)
      c.set_connect_state()
      c.do_handshake()
      c.send('CAPA' + linebreak)
      
      while tls_succeeded == None:
        line = ''
        char = None
        while char != '\n':
          char = c.read(1)
          if not char:
            break
          elif char == '.':
            tls_succeeded = False
          line += char

        if '-ERR' in line:
          tls_succeeded = False
        elif '+OK' in line:
          tls_succeeded = True
        elif not line:
          tls_succeeded = False

    except socket.error, e: 
      plog('WARN', 'Connection to ' + address + ':' + port + ' refused')
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE
    except OpenSSL.SSL.SysCallError, e:
      plog('WARN', 'Error while negotiating an SSL connection to ' + address + ':' + port)
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE

    # reset the connection to default
    socket.socket = defaultsocket

    # check whether the test was valid at all
    exit_node = self.mt.get_exit_node()
    if exit_node == 0 or exit_node == '0':
      plog('INFO', 'We had no exit node to test, skipping to the next test.')
      return TEST_SUCCESS

    # do the same for the direct connection

    capabilities_ok_d = False
    starttls_present_d = False
    tls_started_d = None
    tls_succeeded_d = None

    try:
      pop = Client(address, port)
    
      # read the server greeting
      server_greeting = pop.readline()

      # get the server capabilities
      pop.writeline('CAPA')
      capabilities = ''
      while 1:
        curr = pop.readline()
        if '+OK' in curr:
          capabilities_ok_d = True
        elif curr == '.':
          break
        elif 'STLS' in curr:
          starttls_present_d = True
      
      if not capabilities_ok_d:
        return TEST_INCONCLUSIVE

      # try to start tls negotiation
      if starttls_present_d:
        pop.writeline('STLS')

      starttls_started_d = '+OK' in starttls_response

      # negotiate TLS, issue some request to feel good about it
      ctx = SSL.Context(SSL.SSLv23_METHOD)
      c = SSL.Connection(ctx, pop.sock)
      c.set_connect_state()
      c.do_handshake()
      c.send('CAPA' + linebreak)
      
      while tls_succeeded_d == None:
        line = ''
        char = None
        while char != '\n':
          char = c.read(1)
          if not char:
            break
          elif char == '.':
            tls_succeeded_d = False
          line += char

        if '-ERR' in line:
          tls_succeeded_d = False
        elif '+OK' in line:
          tls_succeeded_d = True
        elif not line:
          tls_succeeded_d = False

    except socket.error, e: 
      plog('WARN', 'Connection to ' + address + ':' + port + ' refused')
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE
    except OpenSSL.SSL.SysCallError, e:
      plog('WARN', 'Error while negotiating an SSL connection to ' + address + ':' + port)
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE

    # compare
    if (capabilities_ok != capabilities_ok_d or starttls_present != starttls_present_d or 
        tls_started != tls_started_d or tls_succeeded != tls_succeeded_d):
      result = POPTestResult(exit_node, address, TEST_FAILURE)
      self.datahandler.saveResult(result)
      # XXX: Log?
      return TEST_FAILURE
    
    result = POPTestResult(exit_node, address, TEST_SUCCESS)
    self.datahandler.saveResult(result)
    return TEST_SUCCESS

class SMTPSTest(Test):
  def __init__(self, mt):
    Test.__init__(self, mt, "SMTPS", 587)

  def run_test(self):
    self.tests_run += 1
    return self.check_smtp(random.choice(self.targets))

  def get_targets(self):
    return [('smtp.gmail.com','587')]

  def check_smtp(self, address, port=''):
    ''' 
    check whether smtp + tls connection to a given address is molested
    this is done by going through the STARTTLS sequence and comparing server
    responses for the direct and tor connections
    '''

    plog('INFO', 'Conducting an smtp test with destination ' + address)

    defaultsocket = socket.socket
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
    socket.socket = socks.socksocket

    ehlo1_reply = 0
    has_starttls = 0
    ehlo2_reply = 0

    try:
      s = smtplib.SMTP(address, port)
      ehlo1_reply = s.ehlo()[0]
      if ehlo1_reply != 250:
        raise smtplib.SMTPException('First ehlo failed')
      has_starttls = s.has_extn('starttls')
      if not has_starttls:
        raise smtplib.SMTPException('It seems the server doesn\'t support starttls')
      s.starttls()
      # TODO check certs?
      ehlo2_reply = s.ehlo()[0]
      if ehlo2_reply != 250:
        raise smtplib.SMTPException('Second ehlo failed')
    except socket.gaierror, e:
      plog('WARN', 'A connection error occured while testing smtp at ' + address)
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE
    except smtplib.SMTPException, e:
      plog('WARN','An error occured while testing smtp at ' + address)
      plog('WARN', e)
      return TEST_INCONCLUSIVE
    # reset the connection method back to direct
    socket.socket = defaultsocket 

    # check whether the test was valid at all
    exit_node = self.mt.get_exit_node()
    if exit_node == 0 or exit_node == '0':
      plog('INFO', 'We had no exit node to test, skipping to the next test.')
      return TEST_SUCCESS

    # now directly

    ehlo1_reply_d = 0
    has_starttls_d = 0
    ehlo2_reply_d = 0

    try:
      s = smtplib.SMTP(address, port)
      ehlo1_reply_d = s.ehlo()[0]
      if ehlo1_reply != 250:
        raise smtplib.SMTPException('First ehlo failed')
      has_starttls_d = s.has_extn('starttls')
      if not has_starttls_d:
        raise smtplib.SMTPException('It seems that the server doesn\'t support starttls')
      s.starttls()
      ehlo2_reply_d = s.ehlo()[0]
      if ehlo2_reply_d != 250:
        raise smtplib.SMTPException('Second ehlo failed')
    except socket.gaierror, e:
      plog('WARN', 'A connection error occured while testing smtp at ' + address)
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE
    except smtplib.SMTPException, e:
      plog('WARN', 'An error occurred while testing smtp at ' + address)
      plog('WARN', e)
      return TEST_INCONCLUSIVE

    print ehlo1_reply, ehlo1_reply_d, has_starttls, has_starttls_d, ehlo2_reply, ehlo2_reply_d

    # compare
    if ehlo1_reply != ehlo1_reply_d or has_starttls != has_starttls_d or ehlo2_reply != ehlo2_reply_d:
      result = SMTPTestResult(exit_node, address, TEST_FAILURE)
      self.datahandler.saveResult(result)
      # XXX: Log?
      return TEST_FAILURE

    result = SMTPTestResult(exit_node, address, TEST_SUCCESS)
    self.datahandler.saveResult(result)
    return TEST_SUCCESS


class IMAPSTest(Test):
  def __init__(self, mt):
    Test.__init__(self, mt, "IMAPS", 143)

  def run_test(self):
    self.tests_run += 1
    return self.check_imap(random.choice(self.targets))

  def get_targets(self):
    return []

  def check_imap(self, address, port=''):
    ''' 
    check whether an imap + tls connection to a given address is molested 
    it is implied that the server reads/sends messages compliant with RFC3501
    ''' 
    plog('INFO', 'Conducting an imap test with destination ' + address)

    if not port:
      port = 143

    defaultsocket = socket.socket
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
    socket.socket = socks.socksocket
    
    capabilities_ok = None
    starttls_present = None
    tls_started = None
    tls_succeeded = None

    try:
      imap = Client(address, port)

      # read server greeting
      server_greeting = imap.readline()

      # get server capabilities
      imap.writeline('a001 CAPABILITY')
      capabilities = imap.readline() # first line - list of capabilities
      capabilities_ok = 'OK' in imap.readline() # second line - the request status
    
      if not capabilities_ok:
         return TEST_INCONCLUSIVE

      # check if starttls is present
      starttls_present = 'STARTTLS' in capabilities

      if starttls_present:
        imap.writeline('a002 STARTTLS')
        tls_started = 'OK' in imap.readline()

      # negotiate TLS, issue a request to feel good about it
      # TODO check the cert aswell ?
      ctx = SSL.Context(SSL.SSLv23_METHOD)
      c = SSL.Connection(ctx, imap.sock)
      c.set_connect_state()
      c.do_handshake()
      c.send('a003 CAPABILITY' + linebreak)
      
      while tls_succeeded == None:
        line = ''
        char = None
        while char != '\n':
          char = c.read(1)
          if not char:
            break
          line += char

        if 'Error' in line or 'error' in line:
          tls_succeeded = False
        elif 'OK' in line:
          tls_succeeded = True
        elif not line:
          tls_succeeded = False
  
    except socket.error, e: 
      plog('WARN', 'Connection to ' + address + ':' + port + ' refused')
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE
    except OpenSSL.SSL.SysCallError, e:
      plog('WARN', 'Error while negotiating an SSL connection to ' + address + ':' + port)
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE
    
    socket.socket = defaultsocket 

    # check whether the test was valid at all
    exit_node = self.mt.get_exit_node()
    if exit_node == 0 or exit_node == '0':
      plog('INFO', 'We had no exit node to test, skipping to the next test.')
      return TEST_SUCCESS

    # do the same for the direct connection
    capabilities_ok_d = None
    starttls_present_d = None
    tls_started_d = None
    tls_succeeded_d = None

    try:
      imap = Client(address, port)

      # read server greeting
      server_greeting = imap.readline()

      # get server capabilities
      imap.writeline('a001 CAPABILITY')
      capabilities = imap.readline() # first line - list of capabilities
      capabilities_ok_d = 'OK' in imap.readline() # second line - the request status

      if not capabilities_ok_d:
        return TEST_INCONCLUSIVE

      # check if starttls is present
      starttls_present_d = 'STARTTLS' in capabilities

      if starttls_present_d:
        imap.writeline('a002 STARTTLS')
        tls_started = 'OK' in imap.readline()

      # negotiate TLS, issue some request to feel good about it
      ctx = SSL.Context(SSL.SSLv23_METHOD)
      c = SSL.Connection(ctx, imap.sock)
      c.set_connect_state()
      c.do_handshake()
      c.send('a003 CAPABILITY' + linebreak)

      while tls_succeeded_d == None:
        line = ''
        char = None
        while char != '\n':
          char = c.read(1)
          if not char:
            break
          line += char

        if 'Error' in line or 'error' in line:
          tls_succeeded_d = False
        elif 'OK' in line:
          tls_succeeded_d = True
        elif not line:
          tls_succeeded_d = False

    except socket.error, e: 
      plog('WARN', 'Connection to ' + address + ':' + port + ' refused')
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE
    except OpenSSL.SSL.SysCallError, e:
      plog('WARN', 'Error while negotiating an SSL connection to ' + address + ':' + port)
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE

    # compare
    if (capabilities_ok != capabilities_ok_d or starttls_present != starttls_present_d or 
      tls_started != tls_started_d or tls_succeeded != tls_succeeded_d):
      result = IMAPTestResult(exit_node, address, TEST_FAILURE)
      self.datahandler.saveResult(result)
      # XXX: log?
      return TEST_FAILURE

    result = IMAPTestResult(exit_node, address, TEST_SUCCESS)
    self.datahandler.saveResult(result)
    return TEST_SUCCESS

class DNSTest(Test):
  def check_dns(self, address):
    ''' A basic comparison DNS test. Rather unreliable. '''
    # TODO Spawns a lot of false positives (for ex. doesn't work for google.com). 
    # XXX: This should be done passive like the DNSRebind test (possibly as
    # part of it)
    plog('INFO', 'Conducting a basic dns test for destination ' + address)

    ip = tor_resolve(address)

    # check whether the test was valid at all
    exit_node = self.mt.get_exit_node()
    if exit_node == 0 or exit_node == '0':
      plog('INFO', 'We had no exit node to test, skipping to the next test.')
      return TEST_SUCCESS

    ips_d = Set([])
    try:
      results = socket.getaddrinfo(address,None)
      for result in results:
        ips_d.add(result[4][0])
    except socket.herror, e:
      plog('WARN', 'An error occured while performing a basic dns test')
      plog('WARN', e)
      return TEST_INCONCLUSIVE

    if ip in ips_d:
      result = DNSTestResult(exit_node, address, TEST_SUCCESS)
      return TEST_SUCCESS
    else:
      plog('ERROR', 'The basic DNS test suspects ' + exit_node + ' to be malicious.')
      result = DNSTestResult(exit_node, address, TEST_FAILURE)
      return TEST_FAILURE

class SSHTest(Test):
  def check_openssh(self, address):
    ''' check whether an openssh connection to a given address is molested '''
    # TODO
    #ssh = pyssh.Ssh('username', 'host', 22)
    #ssh.set_sshpath(pyssh.SSH_PATH)
    #response = self.ssh.sendcmd('ls')
    #print response

    return 0 


# a simple interface to handle a socket connection
class Client:
  def __init__(self, host, port):
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.connect((host, port))
    self.buffer = self.sock.makefile('rb')

  def writeline(self, line):
    self.sock.send(line + linebreak)

  def readline(self):
    response = self.buffer.readline()
    if not response:
      raise EOFError
    elif response[-2:] == linebreak:
      response = response[:-2]
    elif response[-1:] in linebreak:
      response = response[:-1]
    return response 

class NodeManager(EventHandler):
  ''' 
  A tor control event handler extending TorCtl.EventHandler.
  Monitors NS and NEWDESC events, and updates each test
  with new nodes
  '''
  def __init__(self, c):
    EventHandler.__init__(self)
    self.c = c
    self.routers = {}
    self.sorted_r = []
    self.rlock = threading.Lock()
    self._read_routers(self.c.get_network_status())
    self.new_nodes=True
    c.set_event_handler(self)
    c.set_events([TorCtl.EVENT_TYPE.NEWDESC, TorCtl.EVENT_TYPE.NS], True)

  def has_new_nodes(self):
    ret = False
    plog("DEBUG", "has_new_nodes begin")
    try:
      self.rlock.acquire()
      ret = self.new_nodes
      self.new_nodes = False
    finally:
      self.rlock.release()
    plog("DEBUG", "has_new_nodes end")
    return ret

  def get_nodes_for_port(self, port):
    ''' return a list of nodes that allow exiting to a given port '''
    plog("DEBUG", "get_nodes_for_port begin")
    restriction = NodeRestrictionList([FlagsRestriction(["Running", "Valid",
"Fast"]), MinBWRestriction(min_node_bw), ExitPolicyRestriction('255.255.255.255', port)])
    try:
      self.rlock.acquire()
      ret = [x for x in self.sorted_r if restriction.r_is_ok(x)]
    finally:
      self.rlock.release()
    plog("DEBUG", "get_nodes_for_port end")
    return ret
 
  def _read_routers(self, nslist):
    routers = self.c.read_routers(nslist)
    new_routers = []
    for r in routers:
      if r.idhex in self.routers:
        if self.routers[r.idhex].nickname != r.nickname:
          plog("NOTICE", "Router "+r.idhex+" changed names from "
             +self.routers[r.idhex].nickname+" to "+r.nickname)
        self.sorted_r.remove(self.routers[r.idhex])
      self.routers[r.idhex] = r
      new_routers.append(r)

    self.sorted_r.extend(new_routers)
    self.sorted_r.sort(lambda x, y: cmp(y.bw, x.bw))
    # This is an OK update because of the GIL (also we don't touch it)
    for i in xrange(len(self.sorted_r)): self.sorted_r[i].list_rank = i

  def ns_event(self, n):
    plog("DEBUG", "ns_event begin")
    try:
      self.rlock.acquire()
      self._read_routers(n.nslist)
      self.new_nodes = True
    finally:
      self.rlock.release()
    plog("DEBUG", "Read " + str(len(n.nslist))+" NS => " 
       + str(len(self.sorted_r)) + " routers")
  
  def new_desc_event(self, d):
    plog("DEBUG", "new_desc_event begin")
    try:
      self.rlock.acquire()
      for i in d.idlist: # Is this too slow?
        self._read_routers(self.c.get_network_status("id/"+i))
      self.new_nodes = True
    finally:
      self.rlock.release()
    plog("DEBUG", "Read " + str(len(d.idlist))+" Desc => " 
         + str(len(self.sorted_r)) + " routers")
  

class DNSRebindScanner(EventHandler):
  ''' 
  A tor control event handler extending TorCtl.EventHandler 
  Monitors for REMAP events (see check_dns_rebind())
  '''
  def __init__(self, mt, c):
    EventHandler.__init__(self)
    self.__mt = mt
    c.set_event_handler(self)
    c.set_events([TorCtl.EVENT_TYPE.STREAM], True)
    self.c=c


  def stream_status_event(self, event):
    if event.status == 'REMAP':
      octets = map(lambda x: int2bin(x).zfill(8), event.target_host.split('.'))
      ipbin = ''.join(octets)
      for network in ipv4_nonpublic:
        if ipbin[:len(network)] == network:
          handler = DataHandler()
          node = self.__mt.get_exit_node()
          plog("ERROR", "DNS Rebeind failure via "+node)
          result = DNSRebindTestResult(node, '', TEST_FAILURE)
          handler.saveResult(result)

class Metaconnection:
  ''' Abstracts operations with the Metatroller '''
  def __init__(self):
    ''' 
    Establish a connection to metatroller & control port, 
    configure metatroller, load the number of previously tested nodes 
    '''
    # establish a metatroller connection
    try:
      self.__meta = Client(meta_host, meta_port)
    except socket.error:
      plog('ERROR', 'Couldn\'t connect to metatroller. Is it on?')
      exit()
  
    # skip two lines of metatroller introduction
    data = self.__meta.readline()
    data = self.__meta.readline()
    
    # configure metatroller
    commands = [
      'PATHLEN 2',
      'PERCENTFAST 10', # Cheat to win!
      'USEALLEXITS 1',
      'UNIFORM 0',
      'BWCUTOFF 1',
      'ORDEREXITS 1',
      'GUARDNODES 0',
      'RESETSTATS']

    for c in commands:
      self.__meta.writeline(c)
      reply = self.__meta.readline()
      if reply[:3] != '250': # first three chars indicate the reply code
        reply += self.__meta.readline()
        plog('ERROR', 'Error configuring metatroller (' + c + ' failed)')
        plog('ERROR', reply)
        exit()

    # establish a control port connection
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.connect((control_host, control_port))
      c = Connection(s)
      c.authenticate()
      self.__control = c
    except socket.error, e:
      plog('ERROR', 'Couldn\'t connect to the control port')
      plog('ERROR', e)
      exit()
    except AttributeError, e:
      plog('ERROR', 'A service other that the Tor control port is listening on ' + control_host + ':' + control_port)
      plog('ERROR', e)
      exit()
    self.node_manager = NodeManager(c)
   

  def get_exit_node(self):
    ''' ask metatroller for the last exit used '''
    self.__meta.writeline("GETLASTEXIT")
    reply = self.__meta.readline()
    
    if reply[:3] != '250':
      reply += self.__meta.readline()
      plog('ERROR', reply)
      return 0
    
    p = re.compile('250 LASTEXIT=[\S]+')
    m = p.match(reply)
    self.__exit = m.group()[13:] # drop the irrelevant characters  
    plog('INFO','Current node: ' + self.__exit)
    return self.__exit

  def get_new_circuit(self):
    ''' tell metatroller to close the current circuit and open a new one '''
    plog('DEBUG', 'Trying to construct a new circuit')
    self.__meta.writeline("NEWEXIT")
    reply = self.__meta.readline()

    if reply[:3] != '250':
      plog('ERROR', 'Choosing a new exit failed')
      plog('ERROR', reply)

  def set_new_exit(self, exit):
    ''' 
    tell metatroller to set the given node as the exit in the next circuit 
    '''
    plog('DEBUG', 'Trying to set ' + `exit` + ' as the exit for the next circuit')
    self.__meta.writeline("SETEXIT $"+exit)
    reply = self.__meta.readline()

    if reply[:3] != '250':
      plog('ERROR', 'Setting ' + exit + ' as the new exit failed')
      plog('ERROR', reply)

  def report_bad_exit(self, exit):
    ''' 
    report an evil exit to the control port using AuthDirBadExit 
    Note: currently not used  
    '''
    # self.__contol.set_option('AuthDirBadExit', exit) ?
    pass

  # XXX: Hrmm is this in the right place?
  def check_all_exits_port_consistency(self):
    ''' 
    an independent test that finds nodes that allow connections over a common protocol
    while disallowing connections over its secure version (for instance http/https)
    '''

    # get the structure
    routers = self.__control.read_routers(self.__control.get_network_status())
    bad_exits = Set([])
    specific_bad_exits = [None]*len(ports_to_check)
    for i in range(len(ports_to_check)):
      specific_bad_exits[i] = []

    # check exit policies
    for router in routers:
      for i in range(len(ports_to_check)):
        [common_protocol, common_restriction, secure_protocol, secure_restriction] = ports_to_check[i]
        if common_restriction.r_is_ok(router) and not secure_restriction.r_is_ok(router):
          bad_exits.add(router)
          specific_bad_exits[i].append(router)
          #plog('INFO', 'Router ' + router.nickname + ' allows ' + common_protocol + ' but not ' + secure_protocol)
  

    for i,exits in enumerate(specific_bad_exits):
      [common_protocol, common_restriction, secure_protocol, secure_restriction] = ports_to_check[i]
      plog("NOTICE", "Nodes allowing "+common_protocol+" but not "+secure_protocol+":\n\t"+"\n\t".join(map(lambda r: r.nickname+"="+r.idhex, exits)))
      #plog('INFO', 'Router ' + router.nickname + ' allows ' + common_protocol + ' but not ' + secure_protocol)
     

    # report results
    plog('INFO', 'Total nodes: ' + `len(routers)`)
    for i in range(len(ports_to_check)):
      [common_protocol, _, secure_protocol, _] = ports_to_check[i]
      plog('INFO', 'Exits with ' + common_protocol + ' / ' + secure_protocol + ' problem: ' + `len(specific_bad_exits[i])` + ' (~' + `(len(specific_bad_exits[i]) * 100 / len(routers))` + '%)')
    plog('INFO', 'Total bad exits: ' + `len(bad_exits)` + ' (~' + `(len(bad_exits) * 100 / len(routers))` + '%)')

  # XXX: Hrmm is this in the right place?
  def check_dns_rebind(self):
    ''' 
    A DNS-rebind attack test that runs in the background and monitors REMAP events
    The test makes sure that external hosts are not resolved to private addresses  
    '''
    plog('INFO', 'Monitoring REMAP events for weirdness')
    # establish a control port connection
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.connect((control_host, control_port))
      c = Connection(s)
      c.authenticate()
    except socket.error, e:
      plog('ERROR', 'Couldn\'t connect to the control port')
      plog('ERROR', e)
      exit()
    except AttributeError, e:
      plog('ERROR', 'A service other that the Tor control port is listening on ' + control_host + ':' + control_port)
      plog('ERROR', e)
      exit()

    self.__dnshandler = DNSRebindScanner(self, c)


# some helpful methods

def load_wordlist(file):
  ''' load a list of strings from a file (which contains words separated by newlines) '''
  plog('INFO', 'Loading the wordlist')
  
  wordlist = []
  fh = None
  try:
    fh = open(file, 'r')
  except IOError, e:
    plog('ERROR', 'Reading the wordlist file failed.')
    plog('ERROR', e)
  
  try:
    for line in fh:
      wordlist.append(line[:-1]) # get rid of the linebreaks
  finally:
    fh.close()

  return wordlist


def decompress_response_data(response):
  encoding = None

  # a reponse to a httplib.HTTPRequest 
  if (response.__class__.__name__ == "HTTPResponse"):
    encoding = response.getheader("Content-Encoding")
  # a response to urllib2.urlopen()
  elif (response.__class__.__name__ == "addinfourl"):
    encoding = response.info().get("Content-Encoding")

  tot_len = response.info().get("Content-Length")
  if not tot_len:
    tot_len = "0"

  start = time.time()
  data = ""
  while True:
    data_read = response.read(500) # Cells are 495 bytes..
    # XXX: if this doesn't work, check stream observer for 
    # lack of progress.. or for a sign we should read..
    len_read = len(data)
    now = time.time()

    plog("DEBUG", "Read "+str(len_read)+"/"+str(tot_len))
    # Wait 5 seconds before counting data
    if (now-start) > 5 and len_read/(now-start) < min_rate:
      plog("WARN", "Minimum xfer rate not maintained. Aborting xfer")
      return ""
      
    if not data_read:
      break
    data += data_read 
 
  if encoding == 'gzip' or encoding == 'x-gzip':
    return gzip.GzipFile('', 'rb', 9, StringIO.StringIO(data)).read()
  elif encoding == 'deflate':
    return StringIO.StringIO(zlib.decompress(data)).read()
  else:
    return data

def tor_resolve(address):
  ''' performs a DNS query explicitly via tor '''
  return commands.getoutput("tor-resolve " + address)

def int2bin(n):
  '''
  simple decimal -> binary conversion, needed for comparing IP addresses 
  '''
  n = int(n)
  if n < 0:
    raise ValueError, "Negative values are not accepted."
  elif n == 0:
    return '0'
  else:
    bin = ''
    while n > 0:
      bin += str(n % 2)
      n = n >> 1
    return bin[::-1]


class NoURLsFound(Exception):
  pass

#
# main logic
#
def main(argv):
  # make sure we have something to test for
  if len(argv) < 2:
    print ''
    print 'Please provide at least one test option:'
    print '--ssl'
    print '--http'
    print '--html'
#    print '--ssh (doesn\'t work yet)'
#    print '--smtp (~works)'
#    print '--pop (~works)'
#    print '--imap (~works)'
    print '--dnsrebind (use with one or more of above tests)'
    print '--policies'
    print ''
    return

  opts = ['ssl','html','http','ssh','smtp','pop','imap','dns','dnsrebind','policies']
  flags, trailer = getopt.getopt(argv[1:], [], opts)
  
  # get specific test types
  do_ssl = ('--ssl','') in flags
  do_http = ('--http','') in flags
  do_html = ('--html','') in flags
  do_ssh = ('--ssh','') in flags
  do_smtp = ('--smtp','') in flags
  do_pop = ('--pop','') in flags
  do_imap = ('--imap','') in flags
  do_dns_rebind = ('--dnsrebind','') in flags
  do_consistency = ('--policies','') in flags

  # initiate the connection to the metatroller
  mt = Metaconnection()

  # initiate the passive dns rebind attack monitor
  if do_dns_rebind:
    mt.check_dns_rebind()

  # check for sketchy exit policies
  if do_consistency:
    mt.check_all_exits_port_consistency()

  # maybe only the consistency test was required
  if not (do_ssl or do_html or do_http or do_ssh or do_smtp or do_pop or do_imap):
    plog('INFO', 'Done.')
    return

  # Load the cookie jar
  global search_cookies
  search_cookies = cookielib.LWPCookieJar()
  if os.path.isfile(search_cookie_file):
    search_cookies.load(search_cookie_file)
  search_cookies.__filename = search_cookie_file

  tests = {}

  # FIXME: Create an event handler that updates these lists
  if do_ssl:
    try:
      tests["SSL"] = SSLTest(mt, load_wordlist(ssl_wordlist_file))
    except NoURLsFound, e:
      plog('ERROR', e.message)

  if do_http:
    try:
      tests["HTTP"] = HTTPTest(mt, load_wordlist(filetype_wordlist_file))
    except NoURLsFound, e:
      plog('ERROR', e.message)

  if do_html:
    try:
      tests["HTML"] = HTMLTest(mt, load_wordlist(html_wordlist_file))
    except NoURLsFound, e:
      plog('ERROR', e.message)

  if do_smtp:
    try:
      tests["SMTPS"] = SMTPSTest(mt)
    except NoURLsFound, e:
      plog('ERROR', e.message)
    
  if do_pop:
    try:
      tests["POPS"] = POP3STest(mt) 
    except NoURLsFound, e:
      plog('ERROR', e.message)

  if do_imap:
    try:
      tests["IMAPS"] = IMAPSTest(mt)
    except NoURLsFound, e:
      plog('ERROR', e.message)

  # maybe no tests could be initialized
  if not (do_ssl or do_html or do_http or do_ssh or do_smtp or do_pop or do_imap):
    plog('INFO', 'Done.')
    sys.exit(0)
  
  for test in tests.itervalues():
    test.rewind()
  
  # start testing
  while 1:
    avail_tests = tests.values()
    if mt.node_manager.has_new_nodes():
      plog("INFO", "Got signal for node update.")
      for test in avail_tests:
        test.update_nodes()
      plog("INFO", "Note update complete.")

    # Get as much milage out of each exit as we safely can:
    # Run a random subset of our tests in random order
    n_tests = random.choice(xrange(1,len(avail_tests)+1))
    
    to_run = random.sample(avail_tests, n_tests)

    common_nodes = None
    # Do set intersection and reuse nodes for shared tests
    for test in to_run:
      if not common_nodes: common_nodes = Set(map(lambda n: n.idhex, test.nodes))
      else: common_nodes &= Set(map(lambda n: n.idhex, test.nodes))

    if common_nodes:
      current_exit_idhex = random.choice(list(common_nodes))
      plog("DEBUG", "Chose to run "+str(n_tests)+" tests via "+current_exit_idhex+" (tests share "+str(len(common_nodes))+" exit nodes)")

      mt.set_new_exit(current_exit_idhex)
      mt.get_new_circuit()
      for test in to_run:
        # Keep testing failures and inconclusives
        result = test.run_test()
        if result == TEST_SUCCESS:
          test.mark_chosen(test.node_map[current_exit_idhex])
        plog("INFO", test.proto+" test via "+current_exit_idhex+" has result "+str(result))
        plog("INFO", test.proto+" attempts: "+str(test.tests_run)+". Completed: "+str(test.nodes_marked)+"/"+str(test.total_nodes)+" ("+str(test.percent_complete())+"%)")
    else:
      plog("NOTICE", "No nodes in common between "+", ".join(map(lambda t: t.proto, to_run)))
      for test in to_run:
        current_exit = test.get_node()
        mt.set_new_exit(current_exit.idhex)
        mt.get_new_circuit()
        # Keep testing failures and inconclusives
        result = test.run_test()
        plog("INFO", test.proto+" test via "+current_exit.idhex+" has result "+str(result))
        plog("INFO", test.proto+" attempts: "+str(test.tests_run)+". Completed: "+str(test.nodes_marked)+"/"+str(test.total_nodes)+" ("+str(test.percent_complete())+"%)")
        if result == TEST_SUCCESS:
          test.mark_chosen(current_exit)
     
    # Check each test for rewind 
    for test in tests.itervalues():
      if test.finished():
        plog("NOTICE", test.proto+" test has finished all nodes.  Rewinding")
        test.rewind() 
    

# initiate the program
#
if __name__ == '__main__':
  try:
    main(sys.argv)
  except KeyboardInterrupt:
    plog('INFO', "Ctrl + C was pressed. Exiting ... ")
    traceback.print_exc()
  except Exception, e:
    plog('ERROR', "An unexpected error occured.")
    traceback.print_exc()
