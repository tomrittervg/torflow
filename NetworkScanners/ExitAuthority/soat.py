#!/usr/bin/python2.6

# 2008 Aleksei Gorny, mentored by Mike Perry
# 2009 Mike Perry
# 2011 Christian Anderson

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

import atexit
import cookielib
import copy
import getopt
import httplib
import mimetypes
import os
import random
import re
import signal
import smtplib
import socket
import sys
import threading
import time
import traceback
import urllib
import urllib2
import urlparse
import zlib,gzip
import struct

import Queue
import StringIO

from OpenSSL import SSL, crypto

if sys.version_info < (2, 5):
  from sets import Set as set
  from sha import sha
else:
  from hashlib import sha1 as sha

# Import the correct BeautifulSoup
try:
    # Try system-wide BeautifulSoup
    from BeautifulSoup import __version__ as BS_version
except ImportError:
    # Use static version if it's not found
    sys.path.insert(0, "../libs/BeautifulSoup")
else:
    # For now, if system-wide version is newer than 3.1
    # use the static version instead
    if BS_version.split(".") >= ['3','1','0','0']:
        del sys.modules['BeautifulSoup']
        sys.path.insert(0, "../libs/BeautifulSoup")
from BeautifulSoup import Tag, SoupStrainer, BeautifulSoup


from libsoat import *
from soat_config import *

sys.path.append("../../")
from TorCtl import TorUtil, TorCtl, PathSupport, ScanSupport
from TorCtl.TorUtil import plog

sys.path.insert(0,"../libs")
# Make our SocksiPy use our socket
__origsocket = socket.socket
socket.socket = PathSupport.SmartSocket
import SocksiPy.socks as socks
socket.socket = __origsocket

import Pyssh.pyssh as pyssh

# XXX: really need to standardize on $idhex or idhex :(
# The convention in TorCtl is that nicks have no $, and ids have $.
# We should be using that here too...

# XXX: Handle connectivity failures more gracefully..

# TODO:
# < armadev> mikeperry: something to put on the badnode-detector todo
#   list: make sure that each relay can extend to most other relays.
#   e.g. if a relay can only extend to relays running on ports 80
#   and 443, then it's a bad relay.


search_cookies=None
scanhdlr=None
datahandler=None
linebreak = '\r\n'

# Do NOT modify this object directly after it is handed to PathBuilder
# Use PathBuilder.schedule_selmgr instead.
# (Modifying the arguments here is OK)
__selmgr = PathSupport.SelectionManager(
      pathlen=2,
      order_exits=True,
      percent_fast=10, # XXX: This is fingerprintble..
      percent_skip=0,
      min_bw=1,
      use_all_exits=True,
      uniform=False,
      use_exit=None,
      use_guards=False,
      exit_ports=[443])

# Needed for our own sigalarm-based timeouts.
# We can't use socket.timeout because it is a different
# identifier when we are using socksipy's 'socket'
class ReadTimeout(Exception):
  pass

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


def torify(func, *args):
  defaultsocket = socket.socket
  socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TorUtil.tor_host, TorUtil.tor_port)
  socket.socket = socks.socksocket
  rval = None
  try:
    rval = apply(func, args)
  except:
    PathSupport.SmartSocket.clear_port_table()
    socket.socket = defaultsocket
    raise
  # reset the connection method back to direct
  PathSupport.SmartSocket.clear_port_table()
  socket.socket = defaultsocket
  return rval


# Nice.. HTTPConnection.connect is doing DNS for us! Fix that:
# Hrmm.. suppose we could also bind here.. but BindingSocket is
# more general and may come in handy for other tests.
class NoDNSHTTPConnection(httplib.HTTPConnection):
  def connect(self):
    try:
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
      self.sock.settimeout(read_timeout) # Mnemotronic tonic
      if self.debuglevel > 0:
        print "connect: (%s, %s)" % (self.host, self.port)
      self.sock.connect((str(self.host), self.port))
    except socket.error, msg:
      if self.debuglevel > 0:
        print 'connect fail:', (self.host, self.port)
      if self.sock:
        self.sock.close()
      self.sock = None
    if not self.sock:
      raise socket.error, msg

class NoDNSHTTPHandler(urllib2.HTTPHandler):
  def http_open(self, req):
    return self.do_open(NoDNSHTTPConnection, req)

class NullRedirectHandler(urllib2.HTTPRedirectHandler):
  def http_error_301(self, req, fp, code, msg, headers):
    if 'location' in headers:
      newurl = headers.getheaders('location')[0]
    elif 'uri' in headers:
      newurl = headers.getheaders('uri')[0]
    else:
      return # pass through to http_error_default
    raise RedirectException(code, req.get_full_url(), newurl)
  http_error_302 = http_error_303 = http_error_307 = http_error_301

class ExitScanHandler(ScanSupport.ScanHandler):
  def __init__(self, c, selmgr, strm_selector, fixed_exits=[]):
    ScanSupport.ScanHandler.__init__(self, c, selmgr,
                                     strm_selector=strm_selector)
    self.rlock = threading.Lock()
    self.new_nodes=True
    self.fixed_exits = set([])
    for f in fixed_exits:
      x = self.name_to_key.get(f, f)
      self.fixed_exits.add(x.lstrip("$"))

  def has_new_nodes(self):
    # XXX: Hrmm.. could do this with conditions instead..
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
    cond = threading.Condition()
    def notlambda(this):
      cond.acquire()
      restriction = NodeRestrictionList(\
                     [FlagsRestriction(["Running", "Valid", "Fast"], ["BadExit"]),
                      MinBWRestriction(min_node_bw),
                      ExitPolicyRestriction('255.255.255.255', port)])
      if self.fixed_exits: # XXX: Can this be done with NodeRestrictions?
        cond._result = [x for x in self.sorted_r if restriction.r_is_ok(x) and x.idhex in self.fixed_exits]
      else:
        cond._result = [x for x in self.sorted_r if restriction.r_is_ok(x)]
      self._sanity_check(cond._result)
      cond.notify()
      cond.release()
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()
    plog("DEBUG", "get_nodes_for_port end")
    return cond._result

  def new_consensus_event(self, n):
    plog("DEBUG", "newconsensus_event begin")
    try:
      self.rlock.acquire()
      ScanSupport.ScanHandler.new_consensus_event(self, n)
      self.new_nodes = True
    finally:
      self.rlock.release()
    plog("DEBUG", "newconsensus_event end")

  def new_desc_event(self, d):
    plog("DEBUG", "newdesc_event begin")
    try:
      self.rlock.acquire()
      if ScanSupport.ScanHandler.new_desc_event(self, d):
        self.new_nodes = True
    finally:
      self.rlock.release()
    plog("DEBUG", "newdesc_event end")

  def select_exit_from_set(self, exits):
    # Randomly selects from exits until a valid one is found
    # Returns exit idhex or None if no exit is found
    current_exit_idhex = None
    rand_ord_exits = list(exits)
    random.shuffle(rand_ord_exits)
    for e in rand_ord_exits:
      current_exit_idhex = e
      plog("DEBUG", "Requesting $"+current_exit_idhex+" for next set of tests.")
      self.set_exit_node("$"+current_exit_idhex)
      if self.selmgr.bad_restrictions:
        plog("DEBUG", "$"+current_exit_idhex+" is not available.")
        exits.remove(current_exit_idhex)
        current_exit_idhex = None
      else:
        self.new_exit()
        break
    return current_exit_idhex

  # FIXME: Hrmm is this in the right place?
  def check_all_exits_port_consistency(self):
    '''
    an independent test that finds nodes that allow connections over a
    common protocol while disallowing connections over its secure version
    (for instance http/https)
    '''

    # get the structure
    routers = filter(lambda r: "BadExit" not in r.flags,
                     self.current_consensus().sorted_r)
    bad_exits = set([])
    specific_bad_exits = [None]*len(ports_to_check)
    bad_exit_bw = [0]*len(ports_to_check)
    exit_bw = 0

    for i in range(len(ports_to_check)):
      specific_bad_exits[i] = []

    # check exit policies
    for router in routers:
      if "Exit" in router.flags:
        exit_bw += router.bw
      for i in range(len(ports_to_check)):
        [common_protocol, common_restriction, secure_protocol, secure_restriction] = ports_to_check[i]
        if common_restriction.r_is_ok(router) and not secure_restriction.r_is_ok(router):
          bad_exits.add(router)
          bad_exit_bw[i] += router.bw
          specific_bad_exits[i].append(router)
          #plog('INFO', 'Router ' + router.nickname + ' allows ' + common_protocol + ' but not ' + secure_protocol)


    for i,exits in enumerate(specific_bad_exits):
      [common_protocol, common_restriction, secure_protocol, secure_restriction] = ports_to_check[i]
      plog("NOTICE", str(len(exits))+" nodes ("+str(round(100.0*bad_exit_bw[i]/exit_bw,2))+"%) allowing "+common_protocol+" but not "+secure_protocol+":")
      print "# approved-routers"
      print "\n".join(map(lambda r: "!badexit "+r.idhex+"  # "+r.nickname, exits))
      print "\n# torrc"
      print "\n".join(map(lambda r: "authdirbadexit "+socket.inet_ntoa(struct.pack(">I",r.ip))+"  # "+r.nickname, exits))
      print ""
      #plog('INFO', 'Router ' + router.nickname + ' allows ' + common_protocol + ' but not ' + secure_protocol)


    # report results
    plog('INFO', 'Total nodes: ' + `len(routers)`)
    for i in range(len(ports_to_check)):
      [common_protocol, _, secure_protocol, _] = ports_to_check[i]
      plog('INFO', 'Exits with ' + common_protocol + ' / ' + secure_protocol +
' problem: ' + `len(specific_bad_exits[i])`) # + ' (~' + `(len(specific_bad_exits[i]) * 100 / len(routers))` + '%)')
    plog('INFO', 'Total bad exits: ' + `len(bad_exits)`) # + ' (~' + `(len(bad_exits) * 100 / len(routers))` + '%)')

  # FIXME: Hrmm is this in the right place?
  def check_dns_rebind(self, cookie_file):
    '''
    A DNS-rebind attack test that runs in the background and monitors REMAP
    events The test makes sure that external hosts are not resolved to private
    addresses
    '''
    plog('INFO', 'Monitoring REMAP events for weirdness')
    # establish a control port connection
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.connect((TorUtil.control_host, TorUtil.control_port))
      c = PathSupport.Connection(s)
      c.authenticate_cookie(file(cookie_file, "r"))
    except socket.error, e:
      plog('ERROR', 'Couldn\'t connect to the control port')
      plog('ERROR', e)
      exit()
    except AttributeError, e:
      plog('ERROR', 'A service other that the Tor control port is listening on ' + TorUtil.control_host + ':' + TorUtil.control_port)
      plog('ERROR', e)
      exit()

    self.__dnshandler = DNSRebindScanner(self, c)

class Http_Return:
  def __init__(self, rt):
    (self.code, self.headers, self.new_cookies, self.mime_type, self.content) = rt

# HTTP request handling
def http_request(address, cookie_jar=None, headers=firefox_headers):
  ''' perform a http GET-request and return the content received '''
  request = urllib2.Request(address)
  for h in headers:
    request.add_header(h[0], h[1])

  content = ""
  new_cookies = []
  mime_type = ""
  rval = (None, None, None, None, None)
  try:
    plog("DEBUG", "Starting request for: "+address)
    if cookie_jar != None:
      opener = urllib2.build_opener(NoDNSHTTPHandler, NullRedirectHandler, urllib2.HTTPCookieProcessor(cookie_jar))
      reply = opener.open(request)
      if "__filename" in cookie_jar.__dict__:
        cookie_jar.save(cookie_jar.__filename, ignore_discard=True)
      new_cookies = cookie_jar.make_cookies(reply, request)
    else:
      opener = urllib2.build_opener(NoDNSHTTPHandler, NullRedirectHandler)
      reply = opener.open(request)

    length = reply.info().get("Content-Length")
    if length and int(length) > max_content_size:
      plog("WARN", "Max content size exceeded for "+address+": "+length)
      return Http_Return((reply.code, None, [], "", ""))
    mime_type = reply.info().type.lower()
    reply_headers = HeaderDiffer.filter_headers(reply.info().items())
    reply_headers.add(("mime-type", mime_type))
    plog("DEBUG", "Mime type is "+mime_type+", length "+str(length))
    content = decompress_response_data(reply)
    rval = (reply.code, reply_headers, new_cookies, mime_type, content)
  except (ReadTimeout, socket.timeout), e:
    plog("WARN", "Socket timeout for "+address+": "+str(e))
    rval = (E_TIMEOUT, None, [], "", e.__class__.__name__+str(e))
  except SlowXferException, e:
    rval = (E_SLOWXFER, None, [], "", e.__class__.__name__+str(e))
  except RedirectException, e:
    rval = (e.code, None, [], "", e.new_url)
  except httplib.BadStatusLine, e:
    plog('NOTICE', "HTTP Error during request of "+address+": "+str(e))
    if not e.line:
      rval = (E_NOCONTENT, None, [], "", e.__class__.__name__+"(None)")
    else:
      traceback.print_exc()
      rval = (E_MISC, None, [], "", e.__class__.__name__+str(e))
  except urllib2.HTTPError, e:
    plog('NOTICE', "HTTP Error during request of "+address+": "+str(e))
    if str(e) == "<urlopen error timed out>": # Yah, super ghetto...
      rval = (E_TIMEOUT, None, [], "", e.__class__.__name__+str(e))
    else:
      traceback.print_exc()
      rval = (e.code, None, [], "", e.__class__.__name__+str(e))
  except (ValueError, urllib2.URLError), e:
    if str(e) == "<urlopen error timed out>": # Yah, super ghetto...
      rval = (E_TIMEOUT, None, [], "", e.__class__.__name__+str(e))
    else:
      traceback.print_exc()
      rval = (E_URL, None, [], "", e.__class__.__name__+str(e))
  except socks.Socks5Error, e:
    plog('WARN', 'A SOCKS5 error '+str(e.value[0])+' occured for '+address+": "+str(e))
    code = e.value[0]
    if code < 9:
      code = -float(code)
    else:
      code = E_MISC
    rval = (code, None, [], "", e.__class__.__name__+str(e))
  except KeyboardInterrupt:
    raise KeyboardInterrupt
  except Exception, e:
    plog('WARN', 'An unknown HTTP error occured for '+address+": "+str(e))
    traceback.print_exc()
    rval = (E_MISC, None, [], "", e.__class__.__name__+str(e))
  plog("INFO", "Completed HTTP Reqest for: "+address)
  return Http_Return(rval)


# SSL request handling
def ssl_request(address):
  # The SIGALARM can be triggered outside of the try/except in
  # _ssl_request, so we need to catch socket.timeout here
  try:
    return _ssl_request(address)
  except (ReadTimeout, socket.timeout), e:
    plog("INFO", "SSL Request done with timoeut for address: "+str(address))
    return (E_TIMEOUT, None, "Socket timeout")

def _ssl_request(address, method='TLSv1_METHOD'):
  ''' initiate an ssl connection and return the server certificate '''
  address=str(address) # Unicode hostnames not supported..

  # specify the context
  ctx = SSL.Context(getattr(SSL,method))

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(None)

  def _raise_timeout(signum, frame):
    raise ReadTimeout("SSL connection timed out")
  signal.signal(signal.SIGALRM, _raise_timeout)
  # open an ssl connection
  rval = (None, None, None)
  try:
    c = SSL.Connection(ctx, s)
    c.set_connect_state()
    signal.alarm(int(read_timeout)) # raise a timeout after read_timeout
    c.connect((address, 443)) # DNS OK.
    # XXX: A PEM encoded certificate request was a bizarre and fingerprintable
    # thing to send here. All we actually need to do is perform a handshake,
    # but it might be good to make a simple GET request to further limit
    # fingerprintability.
    # c.send(crypto.dump_certificate_request(crypto.FILETYPE_PEM,request))
    c.do_handshake()
    rval = (0, c.get_peer_certificate(), None)
  except (ReadTimeout, socket.timeout), e:
    rval = (E_TIMEOUT, None, "Socket timeout")
  except socks.Socks5Error, e:
    plog('WARN', 'A SOCKS5 error '+str(e.value[0])+' occured for '+address+": "+str(e))
    code = e.value[0]
    if code < 9:
      code = -float(code)
    else:
      code = E_MISC
    rval = (code, None,  e.__class__.__name__+str(e))
  except crypto.Error, e:
    traceback.print_exc()
    rval = (E_CRYPTO, None, e.__class__.__name__+str(e))
  except (SSL.ZeroReturnError, SSL.WantReadError, SSL.WantWriteError, SSL.WantX509LookupError), e:
    # XXX: None of these are really "errors" per se
    traceback.print_exc()
    rval = (E_MISC, None, e.__class__.__name__+str(e))
  except SSL.SysCallError, e:
    # Errors on the underlying socket will be caught here.
    if e[0] == -1: # unexpected eof
      # Might be an SSLv2 server, but it's unlikely, let's just call it a CONNERROR
      rval = (float(e[0]), None, e[1])
    else:
      traceback.print_exc()
      rval = (E_MISC, None, e.__class__.__name__+str(e))
  except SSL.Error, e:
    signal.alarm(0) # Since we might recurse
    for (lib, func, reason) in e[0]:
      if reason in ('wrong version number','sslv3 alert illegal parameter'):
        # Check if the server supports a different SSL version
        if method == 'TLSv1_METHOD':
          plog('DEBUG','Could not negotiate SSL handshake with %s, retrying with SSLv3_METHOD' % address)
          rval = _ssl_request(address, 'SSLv3_METHOD')
          break
    else:
      plog('WARN', 'An unknown SSL error occured for '+address+': '+str(e))
      traceback.print_exc()
      rval = (E_MISC, None,  e.__class__.__name__+str(e))
  except KeyboardInterrupt:
    signal.alarm(0)
    raise
  except Exception, e:
    plog('WARN', 'An unknown SSL error occured for '+address+': '+str(e))
    traceback.print_exc()
    rval = (E_MISC, None,  e.__class__.__name__+str(e))
  signal.alarm(0)
  plog("INFO", "SSL Request done for addrress: "+str(address))
  return rval

class Targets:
  """
  The class used to store the targets of a Test.

  Supports iteration over all targets and labelling a target with one or more "keys".
  MUST support these methods:
  add -- Add a target. Optional second argument is list of keys. Idempotent.
  remove -- Remove a target. Returns True iff the target was found.
  bykey -- Get a list whose elements match the supplied key.
  __iter__
  __len__
  __getitem__

  """
  def __init__(self):
    self.list = []
    self.lookup = {}
  def add(self, target, keys=[]):
    if not target:
      return
    for pos,entry in enumerate(self.list):
      if entry[0] == target:
        newkeys = set.difference(set(keys),self.list[pos][1])
        self.list[pos][1].update(newkeys)
        break
    else:
      newkeys = set(keys)
      self.list.append((target,newkeys))
    for key in newkeys:
      try:
        self.lookup[key].append(target)
      except KeyError:
        self.lookup[key] = [target]
  def remove(self,target):
    retval = False
    for pos,entry in enumerate(self.list):
      if entry[0] == target:
        for key in self.list[pos][1]:
          self.lookup[key].remove(target)
        self.list.pop(pos)
        retval = True
        break
    return retval
  def bykey(self,key):
    return self.lookup.get(key,[])
  def keys(self):
    return self.lookup.keys()
  def __iter__(self):
    return map(lambda x: x[0], self.list).__iter__()
  def __len__(self):
    return len(self.list)
  def __getitem__(self,index):
    return self.list[index]

# Base Test Classes
class Test:
  """ Base class for our tests """
  def __init__(self, proto, port):
    """Sets the variables that are static for the lifetime of the test and calls self._reset() which sets the variables that are not."""
    self.proto = proto
    self.port = port
    self.min_targets = min_targets
    self.filename = None
    self.rescan_nodes = set([])
    self.nodes = set([])
    self.node_map = {}
    self.banned_targets = set([])
    self.total_nodes = 0
    self.scan_nodes = 0
    self.nodes_to_mark = 0
    self.tests_per_node = num_tests_per_node
    self._reset()
    self._pickle_revision = 8 # Will increment as fields are added

  def run_test(self):
    raise NotImplementedError()

  def depickle_upgrade(self):
    if self._pickle_revision < 1:
      # Convert self.successes table from integers to sets.
      # Yes, this is a hack, and yes, it will bias results
      # away from the filter, but hey, at least it will still run.
      self._pickle_revision = 1
      
      for addr in self.successes.keys():
        if type(self.successes[addr]) == int:
          self.successes[addr] = set(xrange(0,self.successes[addr]))
      plog("INFO", "Upgraded "+self.__class__.__name__+" to v1")
    if self._pickle_revision < 2:
      self._pickle_revision = 2
    if self._pickle_revision < 3:
      self.timeout_fails = {}
      self._pickle_revision = 3
    if self._pickle_revision < 4:
      self.connect_fails = {}
      self._pickle_revision = 4
    if self._pickle_revision < 5:
      self.dns_fails = {}
      self._pickle_revision = 5
    if self._pickle_revision < 6:
      self.dns_fails_per_exit = self.dns_fails
      self.timeout_fails_per_exit = self.timeout_fails
      self.connect_fails_per_exit = {}
      self._pickle_revision = 6
    if self._pickle_revision < 7:
      self.exit_fails_per_exit = {}
      self.timeout_fails = {}
      self.dns_fails = {}
      self._pickle_revision = 7
    if self._pickle_revision < 8:
      self.url_reserve = {}
      self._pickle_revision = 8

  def _is_useable_url(self, url, valid_schemes=None, filetype=None):
    (scheme, netloc, path, params, query, fragment) = urlparse.urlparse(url)
    if netloc.rfind(":") != -1:
      # FIXME: %-encoding?
      port = netloc[netloc.rfind(":")+1:]
      try:
        if int(port) != self.port:
          plog("DEBUG", "Unusable port "+port+" in "+url)
          return False
      except:
        traceback.print_exc()
        plog("WARN", "Unparseable port "+port+" in "+url)
        return False
    if valid_schemes and scheme not in valid_schemes:
      plog("DEBUG", "Unusable scheme "+scheme+" in "+url)
      return False
    if url in self.banned_targets:
      plog("DEBUG", "Banned url "+url)
      return False
    if filetype:
      if url[-len(filetype):] != filetype:
        plog("DEBUG", "Bad filetype for "+url)
        return False
    return True

  def add_target(self, target):
    self.targets.add(target)

  def select_targets(self):
    ret = []
    for key in self.targets.keys():
      ret.extend(map(lambda x: (x,key), self.targets.bykey(key)))
    return ret

  def refill_targets(self):
    map(self.add_target, self.get_targets())
    if not self.targets:
      raise NoURLsFound("No URLS found for protocol "+self.proto)

  def remove_target(self, target, reason="None"):
    self.banned_targets.add(target)
    self.targets.remove(target)
    if target in self.dynamic_fails:
      del self.dynamic_fails[target]
    if target in self.successes:
      del self.successes[target]
    if target in self.exit_fails:
      del self.exit_fails[target]
    if target in self.connect_fails:
      del self.connect_fails[target]
    if target in self.dns_fails:
      del self.dns_fails[target]
    if target in self.timeout_fails:
      del self.timeout_fails[target]
    kill_results = []
    for r in self.results:
      if r.site == target:
        kill_results.append(r)
    for r in kill_results:
      # XXX: Need to re-add this node to our test set
      # (If it is still up)
      if r.status == TEST_FAILURE:
        # Save this new result file in false positive dir
        # and remove old one
        try:
          os.unlink(r.filename)
        except:
          pass
        r.mark_false_positive(reason)
        datahandler.saveResult(r)
      self.results.remove(r)

    self.refill_targets()

  def load_rescan(self, type, since=None):
    self.rescan_nodes = set([])
    results = datahandler.getAll()
    for r in results:
      if r.status == type:
        if not since or r.timestamp >= since:
          self.rescan_nodes.add(r.exit_node)
    plog("INFO", "Loaded "+str(len(self.rescan_nodes))+" nodes to rescan")
    if self.nodes and self.rescan_nodes:
      self.nodes &= self.rescan_nodes
    self.scan_nodes = len(self.nodes)
    self.tests_per_node = num_rescan_tests_per_node
    self.nodes_to_mark = self.scan_nodes*self.tests_per_node

  def toggle_rescan(self):
    if self.rescan_nodes:
      plog("NOTICE", self.proto+" rescan complete. Switching back to normal scan")
      self.rescan_nodes = set([])
      self.tests_per_node = num_tests_per_node
      self.update_nodes()
      return 0
    else:
      plog("NOTICE", self.proto+" switching to recan mode.")
      self.load_rescan(TEST_FAILURE, self.run_start)
      return 1

  def get_node(self):
    return random.choice(list(self.nodes))

  def update_nodes(self):
    nodes = scanhdlr.get_nodes_for_port(self.port)
    self.node_map = {}
    for n in nodes:
      self.node_map[n.idhex] = n
    self.total_nodes = len(nodes)
    self.nodes = set(map(lambda n: n.idhex, nodes))
    marked_nodes = set(self.node_results.keys())
    self.nodes -= marked_nodes # Remove marked nodes
    # Only scan the stuff loaded from the rescan
    if self.rescan_nodes:
      self.nodes &= self.rescan_nodes
    if not self.nodes:
      plog("ERROR", "No nodes remain after rescan load!")
    self.scan_nodes = len(self.nodes)
    self.nodes_to_mark = self.scan_nodes*self.tests_per_node
    scanhdlr._sanity_check(map(lambda id: self.node_map[id],
                     self.nodes))

  def mark_chosen(self, node, result):
    exit_node = scanhdlr.get_exit_node()
    if not exit_node:
      plog("WARN", "Exit node disappeared during scan: "+node)
      return
    exit_node = exit_node.idhex
    if exit_node != node:
      plog("ERROR", "Asked to mark a node that is not current: "+node+" vs "+exit_node)
    plog("INFO", "Marking "+node+" with result "+str(result))
    self.nodes_marked += 1
    if not node in self.node_results:
      self.node_results[node] = []
    self.node_results[node].append(result)
    if len(self.node_results[node]) >= self.tests_per_node:
      self.nodes.remove(node)
      self.scan_nodes = len(self.nodes)
      self.nodes_to_mark = self.scan_nodes*self.tests_per_node
      plog("INFO", "Removed node "+node+". "+str(len(self.nodes))+" nodes remain")
    else:
      plog("DEBUG", "Keeping node "+node+". "+str(len(self.nodes))+" nodes remain. Tests: "+str(len(self.node_results[node]))+"/"+str(self.tests_per_node))

  def timestamp_results(self, ts=None):
    # Mark the result with the time at which the test finished
    if ts is None:
      ts = time.time()
    for result in self.results:
      # Only modify results which are already saved to disk
      if result.filename is not None:
        result.finish_timestamp = ts
        datahandler.saveResult(result)

  def finished(self):
    return not self.nodes

  def percent_complete(self):
    return round(100.0 - (100.0*self.scan_nodes)/self.total_nodes, 1)

  def _remove_false_positive_type(self, failset, failtype, max_rate):
    if self.rescan_nodes:
      return
    to_remove = copy.copy(failset)
    for address in to_remove:
      fails = len(failset[address])

      if (100.0*fails)/(self.site_tests(address)) > max_rate:
        plog("NOTICE", "Excessive "+self.proto+" "+failtype+" ("+str(fails)+"/"+str(self.site_tests(address))+") for "+address+". Removing.")
        self.remove_target(address, failtype)

  def remove_false_positives(self):
    if self.rescan_nodes:
      plog("INFO", "Not removing false positives for rescan of "+self.__class__.__name__)
      return
    else:
      plog("INFO", "Removing false positives for "+self.__class__.__name__)
    self._remove_false_positive_type(self.exit_fails,
                                     FALSEPOSITIVE_DYNAMIC_TOR,
                                     max_exit_fail_pct)
    self._remove_false_positive_type(self.dynamic_fails,
                                     FALSEPOSITIVE_DYNAMIC,
                                     max_dynamic_fail_pct)
    self._remove_false_positive_type(self.connect_fails,
                                     FALSEPOSITIVE_DEADSITE,
                                     max_connect_fail_pct)
    self._remove_false_positive_type(self.dns_fails,
                                     FALSEPOSITIVE_DEADSITE,
                                     max_connect_fail_pct)
    self._remove_false_positive_type(self.timeout_fails,
                                     FALSEPOSITIVE_DEADSITE,
                                     max_connect_fail_pct)
    for r in self.results:
      if not r.confirmed and not r.false_positive and r.status == TEST_FAILURE:
        r.confirmed=True # only save confirmed stuff once.
        datahandler.saveResult(r)

  def _reset(self):
    self.results = []
    # Empty target list for new test
    self.targets = Targets()
    self.tests_run = 0
    self.nodes_marked = 0
    self.run_start = time.time()
    # These are indexed by idhex
    self.connect_fails_per_exit = {}
    self.timeout_fails_per_exit = {}
    self.dns_fails_per_exit = {}
    self.exit_fails_per_exit = {}
    self.node_results = {}
    # These are indexed by target URI:
    self.connect_fails = {}
    self.timeout_fails = {}
    self.dns_fails = {}
    self.exit_fails = {}
    self.successes = {}
    self.dynamic_fails = {}

  def rewind(self):
    self._reset()
    self.update_nodes()
    map(self.add_target, self.get_targets())
    if not self.targets:
      raise NoURLsFound("No URLS found for protocol "+self.proto)

    targets_str = "\n\t".join(map(str,self.targets))
    plog("INFO", "Using the following urls for "+self.proto+" scan:\n\t"+targets_str)

  def site_tests(self, site):
    tot_cnt = 0
    if site in self.successes:
      tot_cnt += len(self.successes[site])
    if site in self.exit_fails:
      tot_cnt += len(self.exit_fails[site])
    if site in self.dynamic_fails:
      tot_cnt += len(self.dynamic_fails[site])
    if site in self.connect_fails:
      tot_cnt += len(self.connect_fails[site])
    if site in self.dns_fails:
      tot_cnt += len(self.dns_fails[site])
    if site in self.timeout_fails:
      tot_cnt += len(self.timeout_fails[site])
    return tot_cnt

  def record_site_stats(self, result, stat):
    if result.site in stat:
      stat[result.site].add(result.exit_node)
    else:
      stat[result.site] = set([result.exit_node])
    result.site_result_rate = (len(stat[result.site]), self.site_tests(result.site))
    return result.site_result_rate

  def record_exit_stats(self, result, stat_per_exit):
    if result.exit_node in stat_per_exit:
      stat_per_exit[result.exit_node] += 1
    else:
      stat_per_exit[result.exit_node] = 1
    result.exit_result_rate = (stat_per_exit[result.exit_node], len(self.node_results.get(result.exit_node,[]))+1)
    return result.exit_result_rate

  def register_success(self, result):
    if self.rescan_nodes:
      result.from_rescan = True
    #datahandler.saveResult(result)
    (win_cnt, total) = self.record_site_stats(result, self.successes)
    plog("INFO", self.proto+" success at "+result.exit_node+". This makes "+str(win_cnt)+"/"+str(total)+" node successes for "+result.site)
    return TEST_SUCCESS

  def register_connect_failure(self, result):
    plog("NOTICE", "Registering connect failure")
    if self.rescan_nodes:
      result.from_rescan = True
    self.results.append(result)

    (similar, exit_count) = self.record_site_stats(result, self.connect_fails)
    (fails, result_count) = self.record_exit_stats(result, self.connect_fails_per_exit)

    if fails > num_connfails_per_node:
      result.exit_result_rate = (fails, result_count + num_connfails_per_node)
      plog("ERROR", self.proto+" connection fail of "+result.reason+" at "+result.exit_node+ \
           ". This makes "+str(similar)+"/"+str(exit_count)+" node failures for "+result.site+ \
           ", and "+str(fails)+" "+result.reason+"s for "+result.exit_node+" out of "+ \
           str(result_count)+" results.")
      # XXX: This throws off the statistics collection
      # del self.connect_fails_per_exit[result.exit_node]
      datahandler.saveResult(result)
      return TEST_FAILURE
    else:
      plog("NOTICE", self.proto+" connect fail at "+result.exit_node+". This makes "+str(fails)+" fails")
      return TEST_INCONCLUSIVE

  def register_dns_failure(self, result):
    plog("NOTICE", "Registering dns failure")
    if self.rescan_nodes:
      result.from_rescan = True
    self.results.append(result)

    (similar, exit_count) = self.record_site_stats(result, self.dns_fails)
    (fails, result_count) = self.record_exit_stats(result, self.dns_fails_per_exit)

    if fails > num_dnsfails_per_node:
      result.exit_result_rate = (fails, result_count + num_dnsfails_per_node)
      plog("ERROR", self.proto+" DNS fail of "+result.reason+" at "+result.exit_node+ \
           ". This makes "+str(similar)+"/"+str(exit_count)+" node failures for "+result.site+ \
           ", and "+str(fails)+" "+result.reason+"s for "+result.exit_node+" out of "+ \
           str(result_count)+" results.")
      # XXX: This throws off the statistics collection
      # del self.dns_fails_per_exit[result.exit_node]
      datahandler.saveResult(result)
      return TEST_FAILURE
    else:
      plog("NOTICE", self.proto+" dns fail at "+result.exit_node+". This makes "+str(fails)+" fails")
      return TEST_INCONCLUSIVE

  def register_timeout_failure(self, result):
    plog("NOTICE", "Registering timeout failure")
    if self.rescan_nodes:
      result.from_rescan = True
    self.results.append(result)

    (similar, exit_count) = self.record_site_stats(result, self.timeout_fails)
    (fails, result_count) = self.record_exit_stats(result, self.timeout_fails_per_exit)

    if fails > num_timeouts_per_node:
      result.exit_result_rate = (fails, result_count + num_timeouts_per_node)
      plog("ERROR", self.proto+" timeout fail of "+result.reason+" at "+result.exit_node+ \
           ". This makes "+str(similar)+"/"+str(exit_count)+" node failures for "+result.site+ \
           ", and "+str(fails)+" "+result.reason+"s for "+result.exit_node+" out of "+ \
           str(result_count)+" results.")
      # XXX: This throws off the statistics collection
      # del self.timeout_fails_per_exit[result.exit_node]
      datahandler.saveResult(result)
      return TEST_FAILURE
    else:
      plog("NOTICE", self.proto+" timeout at "+result.exit_node+". This makes "+str(fails)+" timeouts")
      return TEST_INCONCLUSIVE

  def register_exit_failure(self, result):
    plog("NOTICE", "Registering exit failure")
    if self.rescan_nodes:
      result.from_rescan = True
    self.results.append(result)

    (similar, exit_count) = self.record_site_stats(result, self.exit_fails)
    (fails, result_count) = self.record_exit_stats(result, self.exit_fails_per_exit)

    plog("ERROR", self.proto+" exit-only fail of "+result.reason+" at "+result.exit_node+". This makes "+str(similar)+"/"+str(exit_count)+" node failures for "+result.site)
    datahandler.saveResult(result)
    return TEST_FAILURE

  def register_dynamic_failure(self, result):
    plog("NOTICE", "Registering dynamic failure")
    if self.rescan_nodes:
      result.from_rescan = True
    self.results.append(result)

    (similar, exit_count) = self.record_site_stats(result, self.dynamic_fails)

    plog("ERROR", self.proto+" dynamic fail of "+result.reason+" at "+result.exit_node+". This makes "+str(similar)+"/"+str(exit_count)+" node failures for "+result.site)
    datahandler.saveResult(result)
    return TEST_FAILURE

  def register_inconclusive(self, result):
    if self.rescan_nodes:
      result.from_rescan = True
    self.results.append(result)
    datahandler.saveResult(result)
    return TEST_INCONCLUSIVE

class BaseHTTPTest(Test):
  def __init__(self):
    # FIXME: Handle http urls w/ non-80 ports..
    self.fetch_queue = []
    Test.__init__(self, "HTTP", 80)
    self.save_name = "HTTPTest"
    self.compare_funcs = {'html': self.compare_html, "js": self.compare_js}

  def _reset(self):
    self.httpcode_fails = {}
    self.httpcode_fails_per_exit = {}
    # Default cookie jar for new test
    self.tor_cookie_jar = None
    self.cookie_jar = None
    # Default headers for new test
    self.headers = copy.copy(firefox_headers)

    Test._reset(self)

  def depickle_upgrade(self):
    if self._pickle_revision < 7:
      self.httpcode_fails_per_exit = {}
      self.targets_by_type = self.targets
      self.targets = reduce(list.__add__, self.targets.values(), [])
    Test.depickle_upgrade(self)

  def check_cookies(self):
    # FIXME: This test is badly broken..
    # We probably only want to do this on a per-url basis.. Then
    # we can do the dynamic compare..
    return TEST_SUCCESS
    tor_cookies = "\n"
    plain_cookies = "\n"
    # FIXME: do we need to sort these? So far we have worse problems..
    for cookie in self.tor_cookie_jar:
      tor_cookies += "\t"+cookie.name+":"+cookie.domain+cookie.path+" discard="+str(cookie.discard)+"\n"
    for cookie in self.cookie_jar:
      plain_cookies += "\t"+cookie.name+":"+cookie.domain+cookie.path+" discard="+str(cookie.discard)+"\n"
    if tor_cookies != plain_cookies:
      exit_node = "$"+scanhdlr.get_exit_node().idhex
      plog("ERROR", "Cookie mismatch at "+exit_node+":\nTor Cookies:"+tor_cookies+"\nPlain Cookies:\n"+plain_cookies)
      result = CookieTestResult(self.node_map[exit_node[1:]],
                          TEST_FAILURE, FAILURE_COOKIEMISMATCH, plain_cookies,
                          tor_cookies)
      if self.rescan_nodes:
        result.from_rescan = True
      self.results.append(result)
      datahandler.saveResult(result)
      return TEST_FAILURE
    return TEST_SUCCESS

  def run_test(self):
    # A single test should have a single cookie jar
    self.tor_cookie_jar = cookielib.MozillaCookieJar()
    self.cookie_jar = cookielib.MozillaCookieJar()

    self.tests_run += 1

    self.fetch_queue.extend(self.select_targets())

    plog('INFO',str(self.fetch_queue))

    n_success = n_fail = n_inconclusive = 0

    while self.fetch_queue:
      address, filetype = self.fetch_queue.pop(0)
      # FIXME: Set referrer to random or none for each of these
      result = self.check_http(address,filetype)
      if result == TEST_INCONCLUSIVE:
        n_inconclusive += 1
      if result == TEST_FAILURE:
        n_fail += 1
      if result == TEST_SUCCESS:
        n_success += 1

    # Cookie jars contain locks and can't be pickled. Clear them away.
    self.tor_cookie_jar = None
    self.cookie_jar = None

    if n_fail:
      return TEST_FAILURE
    elif n_inconclusive > 2*n_success: # > 66% inconclusive -> redo
      return TEST_INCONCLUSIVE
    else:
      return TEST_SUCCESS

  def remove_target(self, target, reason="None"):
    # Remove from targets list and targets by type dictionary
    self.targets.remove(target)
    # Delete results in httpcode_fails
    if target in self.httpcode_fails:
      del self.httpcode_fails[target]
    Test.remove_target(self, target, reason)

  def remove_false_positives(self):
    Test.remove_false_positives(self)
    self._remove_false_positive_type(self.httpcode_fails,
                                     FALSEPOSITIVE_HTTPERRORS,
                                     max_httpcode_fail_pct)
  def site_tests(self, site):
    tot_cnt = Test.site_tests(self, site)
    if site in self.httpcode_fails:
      tot_cnt += len(self.httpcode_fails[site])
    return tot_cnt

  def register_http_failure(self, result):
    if self.rescan_nodes:
      result.from_rescan = True
    self.results.append(result)

    (similar, exit_count) = self.record_site_stats(result, self.httpcode_fails)
    (fails, result_count) = self.record_exit_stats(result, self.httpcode_fails_per_exit)

    plog("ERROR", self.proto+" "+result.reason+" at "+result.exit_node+ \
         ". This makes "+str(similar)+"/"+str(exit_count)+" node failures for "+result.site+ \
         ", and "+str(fails)+" "+result.reason+"s for "+result.exit_node+" out of "+ \
         str(result_count)+" results.")
    datahandler.saveResult(result)
    return TEST_FAILURE

  def first_load(self, orig_address, filetype):
    """Loads a page on a direct connection. The signtuare is:
       address (posibly after redirects)
       success (T/F)
       code
       filetype of loaded page (should be null if we failed)"""


    # This is the address that this function will return:
    address = orig_address

    # Reqest the content using a direct connection
    req = http_request(orig_address,self.cookie_jar, self.headers)

    # Make a good faith effort to follow redirects
    count = 0
    trail = set([])
    while (300 <= req.code < 400):
      plog("NOTICE", "Non-Tor HTTP "+str(req.code)+" redirect from "+str(orig_address)+" to "+str(req.content))
      address = req.content
      if address in trail: break
      trail.add(address)
      req = http_request(address, self.cookie_jar, self.headers)

      count += 1
      if count > 4: break

    # Couldn't get past the redirects
    if (300 <= req.code < 400):
      return (address,False,req.code,'')

    # If there was a fatal error, return failure
    if not (200 <= req.code < 300) or not req.content:
      plog("NOTICE", "Non-tor HTTP error "+str(req.code)+" fetching content for "+address)
      return (address, False, req.code,'')

    loaded_filetype = mime_to_filetype(req.mime_type)

    if filetype and filetype != loaded_filetype:
      plog('DEBUG', 'Wrong filetype: ' + loaded_filetype + ' instead of ' + filetype)
      return (address, False, req.code, '')

    self.save_compare_data(address,loaded_filetype,req)

    # Fetch again with different cookies and see if we get the same content
    # Use a different IP address if possible

    empty_cookie_jar = cookielib.MozillaCookieJar()

    BindingSocket.bind_to = refetch_ip
    second_req = http_request(address, empty_cookie_jar, self.headers)
    BindingSocket.bind_to = None

    # If there was a fatal error, return failure
    if not (second_req.code <= 200 < 300) or not second_req.content:
      plog("NOTICE", "Non-tor HTTP error "+str(second_req.code)+" fetching content for "+address)
      return (address, False, second_req.code, '')

    if self.compare(address,loaded_filetype,second_req) != COMPARE_EQUAL:
      return (address, False, second_req.code, '')

    return (address, True, req.code, loaded_filetype)    

  def check_http(self, address, filetype, dynamic = False):
    ''' check whether a http connection to a given address is molested '''

    # The "dynamic" option controls whether we dare grapple with dynamic
    # pages. Currently only False is supported.

    plog('INFO', 'Conducting an http test with destination ' + address)

    # Keep a copy of the cookie jar before mods for refetch or
    # to restore on errors that cancel a fetch
    my_tor_cookie_jar = cookielib.MozillaCookieJar()
    for cookie in self.tor_cookie_jar:
      my_tor_cookie_jar.set_cookie(cookie)

    my_cookie_jar = cookielib.MozillaCookieJar()
    for cookie in self.cookie_jar:
      my_cookie_jar.set_cookie(cookie)

    # CA we should modify our headers so we look like a browser

    # pfoobar means that foobar was acquired over a _p_roxy
    preq = torify(http_request, address, my_tor_cookie_jar, self.headers)
    psha1sum = sha(preq.content)

    exit_node = scanhdlr.get_exit_node()
    if not exit_node:
      # CA: how can this happen?
      plog('NOTICE', 'We had no exit node to test, skipping to the next test.')
      result = HttpTestResult(None,
                              address, TEST_INCONCLUSIVE, INCONCLUSIVE_NOEXIT)
      return self.register_inconclusive(result)

    exit_node = "$"+exit_node.idhex

    # If there is an error loading the page over Tor:
    if not (200 <= preq.code < 300) or not preq.content:
      # And if it doesn't have to do with our SOCKS connection:
      if preq.code not in SOCKS_ERRS:
        plog("NOTICE", exit_node+" had error "+str(preq.code)+" fetching content for "+address)

        direct_req = http_request(address, my_cookie_jar, self.headers)

        # If a direct load is failing, remove this target from future consideration
        if (300 <= direct_req.code < 400):
          self.remove_target(address, INCONCLUSIVE_REDIRECT)
        elif not (200 <= direct_req.code < 300):
          self.remove_target(address, FALSEPOSITIVE_HTTPERRORS)

        # If Tor and direct are failing for the same reason, Tor is off the hook
        if (direct_req.code == preq.code):
          result = HttpTestResult(self.node_map[exit_node[1:]],
                                  address, TEST_INCONCLUSIVE, INCONCLUSIVE_NOLOCALCONTENT)
          return self.register_inconclusive(result)

      #  Error => behavior lookup table
      #  Error code     (Failure reason,        Register method,               Set extra_info to pcontent?)
      err_lookup = \
        {E_SOCKS:       (FAILURE_CONNERROR,     self.register_connect_failure, True), # "General socks error"
         E_POLICY:      (FAILURE_EXITPOLICY,    self.register_connect_failure, True), # "connection not allowed aka ExitPolicy
         E_NETUNREACH:  (FAILURE_NETUNREACH,    self.register_connect_failure, True), # "Net Unreach" ??
         E_HOSTUNREACH: (FAILURE_HOSTUNREACH,   self.register_dns_failure,     False), # "Host Unreach" aka RESOLVEFAILED
         E_REFUSED:     (FAILURE_CONNREFUSED,   self.register_exit_failure,    False), # Connection refused
         E_TIMEOUT:     (FAILURE_TIMEOUT,       self.register_timeout_failure, False), # timeout
         E_SLOWXFER:    (FAILURE_SLOWXFER,      self.register_timeout_failure, False), # Transfer too slow
         E_NOCONTENT:   (FAILURE_NOEXITCONTENT, self.register_exit_failure,    False),
         E_URL:         (FAILURE_URLERROR,      self.register_connect_failure, True),
         E_MISC:        (FAILURE_MISCEXCEPTION, self.register_connect_failure, True)
        }

      if preq.code in err_lookup:
        fail_reason, register, extra_info = err_lookup[preq.code]
      elif 300 <= preq.code < 400: # Exit node introduced a redirect
        plog("NOTICE", "Tor only HTTP "+str(preq.code)+" redirect from "+address+" to "+str(preq.content))
        fail_reason = FAILURE_REDIRECT
        register = self.register_http_failure
        extra_info = True
      else: # Exit node introduced some other change
        fail_reason = FAILURE_BADHTTPCODE + str(preq.code) #CA don't think this is good
        register = self.register_exit_failure
        extra_info = True

      # the [1:] gets rid of dollar sign. CA ugly
      result = HttpTestResult(self.node_map[exit_node[1:]],
                              address, TEST_FAILURE, fail_reason)
      if extra_info:
        result.extra_info = str(preq.content)

      return register(result)

    # If we have no content, we had a connection error
    if not preq.content:
      result = HttpTestResult(self.node_map[exit_node[1:]],
                              address, TEST_FAILURE, FAILURE_NOEXITCONTENT)
      return self.register_exit_failure(result)

    #
    # Tor was able to connect, so now it's time to make the comparison
    #

    # Compare the content

    result = self.compare(address,filetype,preq)
    if result == COMPARE_NOEQUAL:
      # Reload direct content and try again
      new_req = http_request(address, my_cookie_jar, self.headers)
      
      # If a new direct load somehow fails, then we're out of luck
      if not (200 <= new_req.code < 300):
        plog("WARN", "Failed to re-frech "+address+" outside of Tor. Did our network fail?")
        self.remove_target(address, FALSEPOSITIVE_HTTPERRORS)
        result = HttpTestResult(self.node_map[exit_node[1:]],
                                address, TEST_INCONCLUSIVE,
                                INCONCLUSIVE_NOLOCALCONTENT)
        return self.register_inconclusive(result)

      # Try our comparison again
      dynamic = self.compare(address,filetype,new_req)
      
      if dynamic == COMPARE_EQUAL:
        # The content has not actually changed, so our exit node is screwing with us.
        result = HttpTestResult(self.node_map[exit_node[1:]],
                                address, TEST_FAILURE, FAILURE_EXITONLY,
                                sha1sum.hexdigest(), psha1sum.hexdigest(),
                                address_to_context(address)+".content")
        retval = self.register_exit_failure(result)

      else:
        # The content is dynamic.
        # Here's where "no dynamic" comes in.
        # We reject this target and mark the test inconclusive.
        plog("WARN", "HTTP Test is removing dynamic URL "+address)
        self.remove_target(address, FALSEPOSITIVE_DYNAMIC)
        result = HttpTestResult(self.node_map[exit_node[1:]],
                                address, TEST_INCONCLUSIVE, INCONCLUSIVE_DYNAMIC,
                                sha1sum_new.hexdigest(), psha1sum.hexdigest(),
                                address_to_context(address)+".content")
        retval = self.register_inconclusive(result)

    elif result == COMPARE_EQUAL:
      result = HttpTestResult(self.node_map[exit_node[1:]],
                              address, TEST_SUCCESS)
      retval = self.register_success(result)

    elif result == COMPARE_TRUNCATION:
      result = HttpTestResult(self.node_map[exit_node[1:]],
                              address, TEST_FAILURE, FAILURE_EXITTRUNCATION,
                              sha1sum.hexdigest(), psha1sum.hexdigest(),
                              content_prefix+".content",
                              exit_content_file)
      retval = self.register_exit_failure(result)

    # If we failed, then store what the exit node handed us
    if retval == TEST_FAILURE:
      exit_content_file = open(address_to_failed_prefix(address)+'.'+exit_node[1:]+'.content', 'w')
      exit_content_file.write(preq.contet)
      exit_content_file.close()

    return retval

  def _address_to_filename(self, address):
    return DataHandler.safeFilename(re.sub('[a-z]+://','',address))

  def address_to_context(self,address):
    return http_content_dir + self._address_to_filename(address)

  def address_to_failed_prefix(self, address):
    return http_failed_dir + self._address_to_filename(address)
    
  def save_compare_data(self, address, filetype, req):
    context = self. address_to_context(address)

    f = open(context + '.content', 'w')
    f.write(req.content)
    f.close()

    lines = req.content.split('\n')
      
    hashes = []
    working_hash = sha()
    for l in lines:
      working_hash.update(l)
      hashes.append(working_hash.hexdigest())

    # Save these line-by-line hashes for later use
    SnakePickler.dump(hashes, context + '.hashes')

    # Save the response headers in case we want them for a later test
    headerdiffer = HeaderDiffer(req.headers)
    SnakePickler.dump(headerdiffer, context + '.headerdiff')

    # Save the new cookies in case we need them for a later test
    SnakePickler.dump(req.new_cookies,context + '.cookies')

  def compare(self,address,filetype,req):
    """The generic function for comparing webcontent."""

    plog('DEBUG', "Beginning Compare")

    context = self. address_to_context(address)

    new_linelist = req.content.split('\n')
 
    f = open(context + '.content')
    old_content = f.read()
    f.close()

    
    old_hashes = SnakePickler.load(context + '.hashes')

    if len(new_linelist) > len(old_hashes):
      retval = COMPARE_NOEQUAL
    else:
      new_hash = sha()
      for i in range(0,min(len(old_hashes),len(new_linelist))):
        new_hash.update(new_linelist[i])
      new_hash = new_hash.hexdigest()

      if new_hash != old_hashes[len(new_linelist) - 1]:
        retval = COMPARE_NOEQUAL
      elif len(new_linelist) == len(old_hashes):
        retval = COMPARE_EQUAL
      else:
        retval = COMPARE_TRUNCATION

    if retval == COMPARE_NOEQUAL:
      try:
        retval = self.compare_funcs[filetype](req.content,old_content,context)
      except KeyError:
        pass

    plog('DEBUG', "Compare got the result: " + str(retval))

    return retval

  def compare_js(self,new_content,old_content,context):
    # TODO check for truncation? Store differ?
    jsdiff = JSDiffer(old_content)
    has_changes = jsdiff.contains_differences(new_content)
    if not has_changes:
      return COMPARE_EQUAL
    else:
      return COMPARE_NOEQUAL

  def compare_html(self,new_content,old_content,context):
    # TODO check for truncation? Store differ?
    old_soup = FullyStrainedSoup(old_content.decode('ascii', 'ignore'))
    new_soup = FullyStrainedSoup(new_content.decode('ascii', 'ignore'))
    htmldiff = SoupDiffer(old_soup,new_soup)
    html_has_changes = htmldiff.content_changed
    # TODO do we need to seperately check JS?
    if not html_has_changes:
      return COMPARE_EQUAL
    else:
      return COMPARE_NOEQUAL

# TODO move these somewhere sensible
def mime_to_filetype(mime_type):
  return mimetypes.guess_extension(mime_type)[1:]

def is_html_mimetype(mime_type):
  is_html = False
  for type_match in html_mime_types:
    if re.match(type_match, mime_type.lower()):
      is_html = True
      break
  return is_html

def is_script_mimetype(mime_type):
  is_script = False
  for type_match in script_mime_types:
    if re.match(type_match, mime_type.lower()):
      is_script = True
      break
  return is_script

class BaseSSLTest(Test):
  def __init__(self):
    Test.__init__(self, "SSL", 443)
    self.save_name = "SSLTest"
    self.test_hosts = num_ssl_hosts

  def run_test(self):
    self.tests_run += 1
    return self.check_ssl(random.choice(self.targets)[0])

  def get_resolved_ip(self, hostname):
    # XXX: This is some extreme GIL abuse.. It may have race conditions
    # on control prot shutdown.. but at that point it's game over for
    # us anyways.
    mappings = scanhdlr.c.get_address_mappings("cache")
    ret = None
    for m in mappings:
      if m.from_addr == hostname:
        if ret:
          plog("WARN", "Multiple maps for "+hostname)
        ret = m.to_addr
    return ret

  def _update_cert_list(self, ssl_domain, check_ips):
    changed = False
    for ip in check_ips:
      #let's always check.
      #if not ssl_domain.seen_ip(ip):
      plog('INFO', 'SSL connection to new ip '+ip+" for "+ssl_domain.domain)
      (code, raw_cert, exc) = ssl_request(ip)
      if not raw_cert:
        plog('WARN', 'Error getting the correct cert for '+ssl_domain.domain+":"+ip+" "+str(code)+"("+str(exc)+")")
        continue
      try:
        ssl_domain.add_cert(ip,
             crypto.dump_certificate(crypto.FILETYPE_PEM, raw_cert))
        changed = True # Always save new copy.
      except Exception, e:
        traceback.print_exc()
        plog('WARN', 'Error dumping cert for '+ssl_domain.domain+":"+ip+" E:"+str(e))
    return changed

  def check_ssl(self, address):
    ''' check whether an https connection to a given address is molested '''
    plog('INFO', 'Conducting an ssl test with destination ' + address)

    # an address representation acceptable for a filename (first 20 chars excluding www.)
    shortaddr = address.replace('www.','',1)[:min(len(address), 20)]
    address_file = DataHandler.safeFilename(shortaddr)
    ssl_file_name = ssl_certs_dir + address_file + '.ssl'

    # load the original cert and compare
    # if we don't have the original cert yet, get it
    try:
      ssl_domain = SnakePickler.load(ssl_file_name)
    except IOError:
      ssl_domain = SSLDomain(address)

    check_ips = []
    resolved = []
    # Make 3 resolution attempts
    for attempt in xrange(1,4):
      try:
        resolved = socket.getaddrinfo(address, 443, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        break
      except socket.gaierror:
        plog("NOTICE", "Local resolution failure #%d for %s" % (attempt, address))

    for res in resolved:
      if res[4][0] not in check_ips:
        check_ips.append(res[4][0])

    if not check_ips:
      plog("WARN", "Local resolution failure for "+address)
      self.remove_target(address, INCONCLUSIVE_NOLOCALCONTENT)
      return TEST_INCONCLUSIVE

    if self._update_cert_list(ssl_domain, check_ips):
      SnakePickler.dump(ssl_domain, ssl_file_name)

    if not ssl_domain.cert_map:
      plog('WARN', 'Error getting the correct cert for ' + address)
      self.remove_target(address, INCONCLUSIVE_NOLOCALCONTENT)
      return TEST_INCONCLUSIVE

    if ssl_domain.cert_changed:
      ssl_domain = SSLDomain(address)
      plog('INFO', 'Fetching all new certs for '+address)
      if self._update_cert_list(ssl_domain, check_ips):
        SnakePickler.dump(ssl_domain, ssl_file_name)
      if ssl_domain.cert_changed:
        plog("NOTICE", "Fully dynamic certificate host "+address)

        result = SSLTestResult("NoExit", "NotStored!", address, ssl_file_name, 
                               TEST_INCONCLUSIVE,
                               INCONCLUSIVE_DYNAMICSSL)
        if self.rescan_nodes:
          result.from_rescan = True
        datahandler.saveResult(result)
        self.results.append(result)
        self.remove_target(address, FALSEPOSITIVE_DYNAMIC)
        return TEST_INCONCLUSIVE

    if not ssl_domain.num_certs():
      plog("NOTICE", "No non-tor certs available for "+address)
      result = SSLTestResult("NoExit", "NoStored!", address, ssl_file_name,
                             TEST_INCONCLUSIVE,
                             INCONCLUSIVE_NOLOCALCONTENT)
      if self.rescan_nodes:
        result.from_rescan = True
      datahandler.saveResult(result)
      self.results.append(result)
      self.remove_target(address, FALSEPOSITIVE_DEADSITE)
      return TEST_INCONCLUSIVE

    # get the cert via tor
    (code, cert, exc) = torify(ssl_request, address)

    exit_node = scanhdlr.get_exit_node()
    if not exit_node:
      plog('NOTICE', 'We had no exit node to test, skipping to the next test.')
      result = SSLTestResult(None,
                              address, ssl_file_name, TEST_INCONCLUSIVE,
                              INCONCLUSIVE_NOEXIT)
      if self.rescan_nodes:
        result.from_rescan = True
      self.results.append(result)
      datahandler.saveResult(result)
      return TEST_INCONCLUSIVE
    exit_node = "$"+exit_node.idhex

    if not cert:
      #  Error code      Failure reason         Register method                Set extra_info to str(exc)?
      err_lookup = \
        {E_SOCKS:       (FAILURE_CONNERROR,     self.register_connect_failure, True), # "General socks error"
         E_POLICY:      (FAILURE_EXITPOLICY,    self.register_connect_failure, True), # "connection not allowed aka ExitPolicy
         E_NETUNREACH:  (FAILURE_NETUNREACH,    self.register_connect_failure, True), # "Net Unreach" ??
         E_HOSTUNREACH: (FAILURE_HOSTUNREACH,   self.register_dns_failure,     False), # "Host Unreach" aka RESOLVEFAILED
         E_REFUSED:     (FAILURE_CONNREFUSED,   self.register_exit_failure,    True), # Connection refused
         E_TIMEOUT:     (FAILURE_TIMEOUT,       self.register_timeout_failure, False), # timeout
         E_SLOWXFER:    (FAILURE_SLOWXFER,      self.register_timeout_failure, False), # Transfer too slow
         E_NOCONTENT:   (FAILURE_NOEXITCONTENT, self.register_exit_failure,    False),
         E_CRYPTO:      (FAILURE_CRYPTOERROR,   self.register_exit_failure,    True),
         E_URL:         (FAILURE_URLERROR,      self.register_connect_failure, True),
         E_MISC:        (FAILURE_MISCEXCEPTION, self.register_connect_failure, True)
        }
      if code in err_lookup:
        fail_reason, register, extra_info = err_lookup[code]
      else:
        fail_reason = FAILURE_MISCEXCEPTION
        register = self.register_connect_failure
        extra_info = False

      result = SSLTestResult(self.node_map[exit_node[1:]],
                             address, ssl_file_name, TEST_FAILURE, fail_reason)
      if extra_info:
        result.extra_info = str(exc)
      return register(result)

    try:
      # get an easily comparable representation of the certs
      cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    except crypto.Error, e:
      result = SSLTestResult(self.node_map[exit_node[1:]],
                   address, ssl_file_name, TEST_FAILURE, FAILURE_CRYPTOERROR)
      self.extra_info=e.__class__.__name__+str(e)
      self.register_exit_failure(result)
      return TEST_FAILURE

    # if certs match, everything is ok
    if ssl_domain.seen_cert(cert_pem):
      result = SSLTestResult(self.node_map[exit_node[1:]],
                             address, ssl_file_name, TEST_SUCCESS)
      self.register_success(result)
      return TEST_SUCCESS

    # False positive case.. Can't help it if the cert rotates AND we have a
    # failure... Need to prune all results for this cert and give up.
    if ssl_domain.cert_rotates:
      result = SSLTestResult(self.node_map[exit_node[1:]],
                             address, ssl_file_name, TEST_FAILURE,
                             FAILURE_DYNAMIC, self.get_resolved_ip(address),
                             cert_pem)
      self.register_dynamic_failure(result)
      return TEST_FAILURE

    # if certs dont match, means the exit node has been messing with the cert
    result = SSLTestResult(self.node_map[exit_node[1:]],
                           address, ssl_file_name, TEST_FAILURE,
                           FAILURE_EXITONLY, self.get_resolved_ip(address),
                           cert_pem)
    self.register_exit_failure(result)
    return TEST_FAILURE

# Fixed Target Tests
class FixedTargetTest:
  """ Mixin class. Must be mixed with a subclass of Test """
  def __init__(self, targets):
    plog('INFO', "You requested the fixed targets: " + str(targets))
    self.fixed_targets = targets

  def get_targets(self):
    return self.fixed_targets[:]

  def refill_targets(self):
    """Can't refill FixedTargetTest"""
    pass

  def finished(self):
    """FixedTargetTests are done if they test all nodes or run out of targets"""
    return not (self.nodes and self.targets)

class FixedTargetHTTPTest(FixedTargetTest, BaseHTTPTest):
  def __init__(self, targets):
    BaseHTTPTest.__init__(self)
    utargets = [t for t in targets if self._is_useable_url(t, ['http'])]
    FixedTargetTest.__init__(self, utargets)

  def get_targets(self): 
    ret = []
    for targ in self.fixed_targets:
      addr, succ, code, ftype = self.first_load(targ, False)
      if succ: 
        ret.append([addr,ftype])
    return ret

  def add_target(self, target):
    self.targets.add(target[0],[target[1]])

class FixedTargetSSLTest(FixedTargetTest, BaseSSLTest):
  def __init__(self, targets):
    BaseSSLTest.__init__(self)
    # We ask for hostnames only, please
    utargets = [t for t in targets if self._is_useable_url(t, [''])]
    FixedTargetTest.__init__(self, utargets)

# Search Based Tests
class SearchBasedTest:
  """ Mixin class. Must be mixed with a subclass of Test """
  def __init__(self, wordlist_file):
    self.wordlist_file = wordlist_file
    self.host_only = False
    self.search_mode = default_search_mode
    self.url_reserve = {}

  def rewind(self):
    self.wordlist = load_wordlist(self.wordlist_file)

  def get_search_urls_for_filetype(self, filetype, number):
    self.url_reserve.setdefault(filetype,[])

    type_urls = set(self.url_reserve[filetype][:number])
    self.url_reserve[filetype] = self.url_reserve[filetype][number:]

    count = 0

    while len(type_urls) < number and count < max_search_retry:
      count += 1

      #Try to filter based on filetype/protocol. Unreliable. We will re-filter.
      query = random.choice(self.wordlist)
      if filetype:
        query += " "+self.search_mode["filetype"]+filetype
      plog("WARN", "RESULTPROTOCOL IS:" + self.result_protocol)
      if self.result_protocol == 'https' and self.search_mode["inurl"]:
        query += " " + self.search_mode["inurl"] + "https"
      #query += '&num=' + `g_results_per_page`

      # search google for relevant pages
      # note: google only accepts requests from idenitified browsers
      host = self.search_mode["host"]
      qdict = {self.search_mode["query"] : query}
      if "extra" in self.search_mode:
        qdict.update(self.search_mode["extra"])
      params = urllib.urlencode(qdict)
      search_path = '?' + params
      search_url = "http://"+host+search_path

      plog("INFO", "Search url: "+search_url)
      try:
        if self.search_mode["useragent"]:
          search_req = http_request(search_url, search_cookies)
        else:
          headers = filter(lambda h: h[0] != "User-Agent",
                           copy.copy(firefox_headers))
          search_req = http_request(search_url, search_cookies, headers)

      except socket.gaierror:
        plog('ERROR', 'Scraping of http://'+host+search_path+" failed")
        traceback.print_exc()
        break
      except:
        plog('ERROR', 'Scraping of http://'+host+search_path+" failed")
        traceback.print_exc()
        # Bloody hack just to run some tests overnight
        break

      if (400 <= search_req.code < 500):
        plog('ERROR', 'Scraping of http://'+host+search_path+' failed. HTTP '+str(code))
        break

      content = search_req.content

      links = SoupStrainer('a')
      try:
        soup = TheChosenSoup(content, parseOnlyThese=links)
      except Exception:
        plog('ERROR', 'Soup-scraping of http://'+host+search_path+" failed")
        traceback.print_exc()
        print "Content is: "+str(content)
        break

      # get the links and do some additional filtering
      assert(self.search_mode["class"])
      for link in soup.findAll('a'):
        #Filter based on class of link
        try:
          if self.search_mode["class"] != link["class"]:
            continue
        except KeyError: continue

        #Get real target
        url = link[self.search_mode['realtgt']]

        if self.result_protocol == 'any':
          prot_list = None
        else:
          prot_list = [self.result_protocol]

        if self._is_useable_url(url, prot_list, filetype):
          try:
            self.first_load
          except AttributeError:
            pass
          else:
            url, success, code, cur_filetype = self.first_load(url,filetype)
            if not success:
              continue

          plog('DEBUG', "Found a useable url: " + url)
          if self.host_only:
            # FIXME: %-encoding, @'s, etc?
            plog("INFO", url)
            url = urlparse.urlparse(url)[1]
            # Have to check again here after parsing the url:
            if host in self.banned_targets:
              plog('DEBUG',"Url was not useable after all (banned): " + url)
              continue
          type_urls.add(url)
          plog("INFO", "Have "+str(len(type_urls))+"/"+str(number)+" urls from search so far..")
        else:
          pass

    if len(type_urls) > number:
      chosen = random.sample(type_urls,number)
      self.url_reserve[filetype].extend(list(type_urls - set(chosen)))
      type_urls = chosen

    plog("INFO","Got urls for filetype!")

    return type_urls

class SearchBasedHTTPTest(SearchBasedTest, BaseHTTPTest):
  def __init__(self, wordlist, scan_filetypes=scan_filetypes):
    BaseHTTPTest.__init__(self)
    SearchBasedTest.__init__(self, wordlist)
    self.scan_filetypes = scan_filetypes
    self.results_per_type = urls_per_filetype
    self.result_protocol = 'http'

  def depickle_upgrade(self):
    if self._pickle_revision < 7:
      self.result_filetypes = self.scan_filetypes
      self.result_protocol = "http"
      self.results_per_type = self.fetch_targets
    BaseHTTPTest.depickle_upgrade(self)

  def rewind(self):
    SearchBasedTest.rewind(self)
    BaseHTTPTest.rewind(self)

  def select_targets(self):
    retval = []
    n_tests = random.randrange(1,len(self.targets.keys())+1)
    filetypes = random.sample(self.targets.keys(), n_tests)
    plog("INFO", "HTTPTest decided to fetch "+str(n_tests)+" urls of types: "+str(filetypes))
    for ftype in filetypes:
      retval.append((random.choice(self.targets.bykey(ftype)),ftype))
    return retval

  def refill_targets(self):
    for ftype in self.scan_filetypes:
      targets_needed = self.results_per_type - len(self.targets.bykey(ftype))
      if targets_needed > 0:
        plog("NOTICE", self.proto+" scanner short on "+ftype+" targets. Adding more")
        map(self.add_target, self.get_search_urls_for_filetype(ftype,targets_needed))

  def add_target(self, target):
    self.targets.add(target[0],[target[1]])
    return True

  def get_targets(self):
    '''
    construct a list of urls based on the wordlist, filetypes and protocol.
    '''
    plog('INFO', 'Searching for relevant sites...')

    urllist = set([])
    for filetype in self.scan_filetypes:
      urllist.update(map(lambda x: (x, filetype), self.get_search_urls_for_filetype(filetype, self.results_per_type)))

    return list(urllist)

HTTPTest = SearchBasedHTTPTest # For resuming from old HTTPTest.*.test files

class SearchBasedSSLTest(SearchBasedTest, BaseSSLTest):
  def __init__(self, wordlist):
    BaseSSLTest.__init__(self)
    SearchBasedTest.__init__(self, wordlist)
    self.host_only = True
    self.result_protocol = 'https'
    try:
      if default_search_mode == yahoo_search_mode:
        plog('WARN', 'Yahoo search mode is not suitable for SSLTests. Continuing anyway.')
    except NameError:
      pass
    self.search_mode=default_search_mode

  def depickle_upgrade(self):
    if self._pickle_revision < 7:
      self.host_only = True
      self.result_protocol = 'https'
      self.search_mode=google_search_mode
    BaseSSLTest.depickle_upgrade(self)

  def get_targets(self):
    '''
    construct a list of urls based on the wordlist, filetypes and protocol.
    '''
    plog('INFO', 'Searching for relevant sites...')

    urllist = set([])
    urllist.update(self.get_search_urls_for_filetype(None, num_ssl_hosts))

    return list(urllist)

  def rewind(self):
    SearchBasedTest.rewind(self)
    BaseSSLTest.rewind(self)

SSLTest = SearchBasedSSLTest # For resuming from old SSLTest.*.test files


class POP3STest(Test):
  def __init__(self):
    Test.__init__(self, "POP3S", 110)

  def run_test(self):
    self.tests_run += 1
    return self.check_pop(random.choice(self.targets))

  def get_targets(self):
    return []

  def check_pop(self, address, port=''):
    '''
    check whether a pop + tls connection to a given address is molested
    it is implied that the server reads/sends messages compliant with RFC1939 & RFC2449
    '''

    plog('INFO', 'Conducting a pop test with destination ' + address)

    if not port:
      port = 110

    defaultsocket = socket.socket
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TorUtil.tor_host,
                          TorUtil.tor_port)
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
    except SSL.SysCallError, e:
      plog('WARN', 'Error while negotiating an SSL connection to ' + address + ':' + port)
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE

    # reset the connection to default
    socket.socket = defaultsocket

    # check whether the test was valid at all
    exit_node = scanhdlr.get_exit_node()
    if not exit_node:
      plog('INFO', 'We had no exit node to test, skipping to the next test.')
      return TEST_INCONCLUSIVE

    exit_node = "$"+exit_node.idhex
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
    except SSL.SysCallError, e:
      plog('WARN', 'Error while negotiating an SSL connection to ' + address + ':' + port)
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE

    # compare
    if (capabilities_ok != capabilities_ok_d or starttls_present != starttls_present_d or
        tls_started != tls_started_d or tls_succeeded != tls_succeeded_d):
      result = POPTestResult(self.node_map[exit_node[1:]], address, TEST_FAILURE)
      datahandler.saveResult(result)
      return TEST_FAILURE

    result = POPTestResult(self.node_map[exit_node[1:]], address, TEST_SUCCESS)
    datahandler.saveResult(result)
    return TEST_SUCCESS

class SMTPSTest(Test):
  def __init__(self):
    Test.__init__(self, "SMTPS", 587)

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
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,
                          TorUtil.tor_host, TorUtil.tor_port)
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
    exit_node = scanhdlr.get_exit_node()
    if not exit_node:
      plog('INFO', 'We had no exit node to test, skipping to the next test.')
      return TEST_INCONCLUSIVE

    exit_node = "$"+exit_node.idhex
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
      result = SMTPTestResult(self.node_map[exit_node[1:]], address, TEST_FAILURE)
      datahandler.saveResult(result)
      return TEST_FAILURE

    result = SMTPTestResult(self.node_map[exit_node[1:]], address, TEST_SUCCESS)
    datahandler.saveResult(result)
    return TEST_SUCCESS


class IMAPSTest(Test):
  def __init__(self):
    Test.__init__(self, "IMAPS", 143)

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
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TorUtil.tor_host,
                          TorUtil.tor_port)
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
    except SSL.SysCallError, e:
      plog('WARN', 'Error while negotiating an SSL connection to ' + address + ':' + port)
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE

    socket.socket = defaultsocket

    # check whether the test was valid at all
    exit_node = scanhdlr.get_exit_node()
    if not exit_node:
      plog('NOTICE', 'We had no exit node to test, skipping to the next test.')
      return TEST_INCONCLUSIVE

    exit_node = "$"+exit_node.idhex
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
    except SSL.SysCallError, e:
      plog('WARN', 'Error while negotiating an SSL connection to ' + address + ':' + port)
      plog('WARN', e)
      socket.socket = defaultsocket
      return TEST_INCONCLUSIVE

    # compare
    if (capabilities_ok != capabilities_ok_d or starttls_present != starttls_present_d or
      tls_started != tls_started_d or tls_succeeded != tls_succeeded_d):
      result = IMAPTestResult(self.node_map[exit_node[1:]], address, TEST_FAILURE)
      datahandler.saveResult(result)
      return TEST_FAILURE

    result = IMAPTestResult(self.node_map[exit_node[1:]], address, TEST_SUCCESS)
    datahandler.saveResult(result)
    return TEST_SUCCESS

class DNSTest(Test):
  def check_dns(self, address):
    ''' A basic comparison DNS test. Rather unreliable. '''
    # TODO Spawns a lot of false positives (for ex. doesn't work for google.com).
    # TODO: This should be done passive like the DNSRebind test (possibly as
    # part of it)
    plog('INFO', 'Conducting a basic dns test for destination ' + address)

    ip = tor_resolve(address)

    # check whether the test was valid at all
    exit_node = scanhdlr.get_exit_node()
    if not exit_node:
      plog('INFO', 'We had no exit node to test, skipping to the next test.')
      return TEST_SUCCESS

    exit_node = "$"+exit_node.idhex
    ips_d = set([])
    try:
      results = socket.getaddrinfo(address,None)
      for result in results:
        ips_d.add(result[4][0])
    except socket.gaierror, e:
      plog('WARN', 'An error occured while performing a basic dns test')
      plog('WARN', e)
      return TEST_INCONCLUSIVE

    if ip in ips_d:
      result = DNSTestResult(self.node_map[exit_node[1:]], address, TEST_SUCCESS)
      return TEST_SUCCESS
    else:
      plog('ERROR', 'The basic DNS test suspects ' + exit_node + ' to be malicious.')
      result = DNSTestResult(self.node_map[exit_node[1:]], address, TEST_FAILURE)
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

class DNSRebindScanner(TorCtl.EventHandler):
  '''
  A tor control event handler extending TorCtl.EventHandler
  Monitors for REMAP events (see check_dns_rebind())
  '''
  def __init__(self, mt, c):
    TorCtl.EventHandler.__init__(self)
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
          node = "$"+self.__mt.get_exit_node().idhex
          plog("ERROR", "DNS Rebeind failure via "+node)

          result = DNSRebindTestResult(self.__mt.node_manager.idhex_to_r(node),
                                       '', TEST_FAILURE)
          handler.saveResult(result)
    # TODO: This is currently handled via socks error codes,
    # but stream events would give us more info...
    #elif event.status == "FAILED" or event.status == "CLOSED":
       # check remote_reason == "RESOLVEFAILED"
       # getinfo.circuit_status()
       # TODO: Check what we do in these detached cases..
       #scanhdlr.name_to_idhex(exit)

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

  def _raise_timeout(signum, frame):
    raise ReadTimeout("HTTP read timed out")
  signal.signal(signal.SIGALRM, _raise_timeout)

  start = 0
  data = ""
  while True:
    signal.alarm(int(read_timeout)) # raise a timeout after read_timeout
    data_read = response.read(500) # Cells are 495 bytes..
    signal.alarm(0)
    if not start:
      start = time.time()
    # TODO: if this doesn't work, check stream observer for
    # lack of progress.. or for a sign we should read..
    len_read = len(data)
    now = time.time()

    #plog("DEBUG", "Read "+str(len_read)+"/"+str(tot_len)) #Very verbose
    # Wait 5 seconds before counting data
    if (now-start) > 5:
      rate = (float(len_read)/(now-start)) #B/s
      if rate < min_rate:
        plog("WARN", "Minimum xfer rate not maintained. Aborting xfer")
        raise SlowXferException("Rate: %.2f KB/s" % (rate/1024))

    if not data_read:
      break
    data += data_read

  plog("INFO", "Completed read")
  if encoding == 'gzip' or encoding == 'x-gzip':
    return gzip.GzipFile('', 'rb', 9, StringIO.StringIO(data)).read()
  elif encoding == 'deflate':
    return StringIO.StringIO(zlib.decompress(data)).read()
  else:
    return data

def tor_resolve(address):
  ''' performs a DNS query explicitly via tor '''
  import commands
  return commands.getoutput("tor-resolve '%s'" % address)

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

def cleanup(c, l, f):
  plog("INFO", "Resetting __LeaveStreamsUnattached=0 and FetchUselessDescriptors="+f)
  try:
    c.set_option("__LeaveStreamsUnattached", l)
    c.set_option("FetchUselessDescriptors", f)
  except TorCtl.TorCtlClosed:
    pass

def setup_handler(out_dir, cookie_file, fixed_exits=[]):
  plog('INFO', 'Connecting to Tor at '+TorUtil.control_host+":"+str(TorUtil.control_port))
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((TorUtil.control_host,TorUtil.control_port))
  c = PathSupport.Connection(s)
  c.debug(file(out_dir+"/control.log", "w", buffering=0))
  c.authenticate_cookie(file(cookie_file, "r"))
  l = c.get_option("__LeaveStreamsUnattached")[0][1]
  h = ExitScanHandler(c, __selmgr, PathSupport.SmartSocket.StreamSelector, fixed_exits)

  c.set_event_handler(h)
  #c.set_periodic_timer(2.0, "PULSE")

  c.set_events([TorCtl.EVENT_TYPE.STREAM,
          TorCtl.EVENT_TYPE.BW,
          TorCtl.EVENT_TYPE.NEWCONSENSUS,
          TorCtl.EVENT_TYPE.NEWDESC,
          TorCtl.EVENT_TYPE.CIRC,
          TorCtl.EVENT_TYPE.STREAM_BW], True)

  c.set_option("__LeaveStreamsUnattached", "1")
  f = c.get_option("FetchUselessDescriptors")[0][1]
  c.set_option("FetchUselessDescriptors", "1")
  atexit.register(cleanup, *(c, l, f))
  return (c,h)


# main logic
def main(argv):
  # make sure we have something to test for
  if len(argv) < 2:
    print ''
    print 'Please provide at least one test option:'
    print '--pernode=<n>'
    print '--resume=<n>'
    print '--rescan=<n>'
    print '--ssl'
    print '--http'
#    print '--ssh (doesn\'t work yet)'
#    print '--smtp (~works)'
#    print '--pop (~works)'
#    print '--imap (~works)'
    print '--dnsrebind (use with one or more of above tests)'
    print '--policies'
    print '--exit=<exit>'
    print '--target=<ip or url>'
    print '--loglevel=<DEBUG|INFO|NOTICE|WARN|ERROR|NONE>'
    print ''
    return
  
  TorUtil.read_config(data_dir+"/torctl.cfg")

  opts = ['ssl','rescan', 'pernode=', 'resume=','http','ssh','smtp','pop','imap','dns','dnsrebind','policies','exit=','target=','loglevel=']
  flags, trailer = getopt.getopt(argv[1:], [], opts)
  
  # get specific test types
  do_resume = False
  do_rescan = ('--rescan','') in flags
  do_ssl = ('--ssl','') in flags
  do_http = ('--http','') in flags
  #do_ssh = ('--ssh','') in flags
  #do_smtp = ('--smtp','') in flags
  #do_pop = ('--pop','') in flags
  #do_imap = ('--imap','') in flags
  do_dns_rebind = ('--dnsrebind','') in flags
  do_consistency = ('--policies','') in flags

  fixed_exits=[]
  fixed_targets=[]
  for flag in flags:
    if flag[0] == "--exit":
      fixed_exits.append(flag[1])
    if flag[0] == "--target":
      fixed_targets.append(flag[1])
    if flag[0] == "--pernode":
      global num_tests_per_node
      num_tests_per_node = int(flag[1])
    if flag[0] == "--rescan" and flag[1]:
      global num_rescan_tests_per_node
      num_rescan_tests_per_node = int(flag[1])
    if flag[0] == "--resume":
      do_resume = True
      resume_run=int(flag[1])
    if flag[0] == "--loglevel":
      if flag[1] in TorUtil.loglevels:
        TorUtil.loglevel=flag[1]
      else:
        plog("ERROR", "Unknown loglevel: "+flag[1])
        sys.exit(0)


  plog("DEBUG", "Read tor config. Got Socks proxy: "+str(TorUtil.tor_port))

  # Make logs go to disk so resumes are less painful
  #TorUtil.logfile = open(log_file_name, "a")

  # initiate the connection to tor
  try:
    global scanhdlr
    (c,scanhdlr) = setup_handler(data_dir,
                                 data_dir+"tor/control_auth_cookie",
                                 fixed_exits)
  except Exception, e:
    traceback.print_exc()
    plog("WARN", "Can't connect to Tor: "+str(e))
    return

  global datahandler
  datahandler = DataHandler()

  # initiate the passive dns rebind attack monitor
  if do_dns_rebind:
    scanhdlr.check_dns_rebind(data_dir+"tor/control_auth_cookie")

  # check for sketchy exit policies
  if do_consistency:
    scanhdlr.check_all_exits_port_consistency()

  # maybe only the consistency test was required
  if not (do_ssl or do_http):
    plog('INFO', 'Done.')
    return

  # Load the cookie jar
  global search_cookies
  search_cookies = cookielib.LWPCookieJar()
  if os.path.isfile(search_cookie_file):
    search_cookies.load(search_cookie_file, ignore_discard=True)
  search_cookies.__filename = search_cookie_file

  tests = {}

  # Check that necessary result directories exist
  dirsok = True
  tocheck = []
  rsubdirs = ['confirmed/', 'falsepositive/', 'rescan/', 'successful/', 'inconclusive/', 'failed/']
  if do_ssl:
    ssl_data_dir = os.path.join(soat_dir, 'ssl')
    tocheck += [ssl_certs_dir]
    tocheck += [os.path.join(ssl_data_dir, r) for r in rsubdirs]
  if do_http:
    tocheck += [http_content_dir]
    tocheck += [os.path.join(http_data_dir, r) for r in rsubdirs]
  if do_dns_rebind:
    rebind_data_dir = os.path.join(soat_dir, 'dnsrebind')
    tocheck += [os.path.join(rebind_data_dir, r) for r in rsubdirs]
  # TODO: Uncomment relevant sections when tests are reenabled
  #if do_ssh:
  #  ssh_data_dir = os.path.join(soat_dir, 'ssh')
  #  tocheck += [os.path.join(ssh_data_dir, r) for r in rsubdirs]
  #if do_smtp:
  #  smtp_data_dir = os.path.join(soat_dir, 'smtp')
  #  tocheck += [os.path.join(smtp_data_dir, r) for r in rsubdirs]
  #if do_pop:
  #  pop_data_dir = os.path.join(soat_dir, 'pop')
  #  tocheck += [os.path.join(pop_data_dir, r) for r in rsubdirs]
  #if do_imap:
  #  imap_data_dir = os.path.join(soat_dir, 'imap')
  #  tocheck += [os.path.join(imap_data_dir, r) for r in rsubdirs]
  for d in tocheck:
    dirsok &= datahandler.checkResultDir(d)
  if not dirsok:
    plog("ERROR", "Could not create result directories")
    return

  # Initialize tests
  if do_resume:
    if do_ssl:
      tests["SSL"] = datahandler.loadTest("SSLTest", resume_run)
      plog("NOTICE", "Resuming previous SSL run "+os.path.split(tests["SSL"].filename)[-1])

    if do_http:
      tests["HTTP"] = datahandler.loadTest("HTTPTest", resume_run)
      plog("NOTICE", "Resuming previous HTTP run "+os.path.split(tests["HTTP"].filename)[-1])

  elif fixed_targets:
    if do_ssl:
      tests["SSL"] = FixedTargetSSLTest(fixed_targets)

    if do_http:
      tests["HTTP"] = FixedTargetHTTPTest(fixed_targets)

  else:
    if do_ssl:
      tests["SSL"] = SearchBasedSSLTest(ssl_wordlist_file)

    if do_http:
      tests["HTTP"] = SearchBasedHTTPTest(filetype_wordlist_file)

  # maybe no tests could be initialized
  if not tests:
    plog('INFO', 'Done.')
    return

  # Make sure refetch_ip is valid rather than exploding mid-test
  global refetch_ip
  BindingSocket.bind_to = refetch_ip
  try:
    socket.socket()
  except socket.error:
    plog("WARN", "Cannot bind to "+refetch_ip+". Ignoring refetch_ip setting.")
    refetch_ip = None
  BindingSocket.bind_to = None

  if do_rescan:
    plog("NOTICE", "Loading rescan.")
    for test in tests.itervalues():
      test.load_rescan(TEST_FAILURE)

  if not do_resume:
    for test in tests.itervalues():
      test.rewind()

  # start testing
  while 1:
    avail_tests = tests.values()
    if scanhdlr.has_new_nodes():
      plog("INFO", "Got signal for node update.")
      for test in avail_tests:
        test.update_nodes()
      plog("INFO", "Node update complete.")

    # Get as much milage out of each exit as we safely can:
    # Run a random subset of our tests in random order
    n_tests = random.choice(xrange(1,len(avail_tests)+1))

    to_run = random.sample(avail_tests, n_tests)

    common_nodes = None
    # Do set intersection and reuse nodes for shared tests
    for test in to_run:
      if test.finished():
        continue
      if not common_nodes:
        common_nodes = copy.copy(test.nodes)
      else:
        common_nodes &= test.nodes
      scanhdlr._sanity_check(map(lambda id: test.node_map[id],
                                             test.nodes))
    print "COMMON NODES"
    print common_nodes

    if common_nodes is None:
      common_nodes = set([])

    current_exit_idhex = scanhdlr.select_exit_from_set(common_nodes)
    any_avail = bool(current_exit_idhex is not None)
    if any_avail:
      plog("DEBUG", "Chose to run "+str(n_tests)+" tests via "+str(current_exit_idhex)+" (tests share "+str(len(common_nodes))+" exit nodes)")
      for test in to_run:
        result = test.run_test()
        if result != TEST_INCONCLUSIVE:
          test.mark_chosen(current_exit_idhex, result)
        datahandler.saveTest(test)
        plog("INFO", test.proto+" test via "+current_exit_idhex+" has result "+str(result))
        plog("INFO", test.proto+" attempts: "+str(test.tests_run)+".  Completed: "+str(test.total_nodes - test.scan_nodes)+"/"+str(test.total_nodes)+" ("+str(test.percent_complete())+"%)")
    elif len(to_run) > 1:
      plog("NOTICE", "No nodes in common between "+", ".join(map(lambda t: t.proto, to_run)))
      for test in to_run:
        if test.finished():
          continue
        current_exit_idhex = scanhdlr.select_exit_from_set(test.nodes.copy())
        if current_exit_idhex:
          any_avail = True
          result = test.run_test()
          if result != TEST_INCONCLUSIVE:
            test.mark_chosen(current_exit_idhex, result)
          datahandler.saveTest(test)
          plog("INFO", test.proto+" test via "+current_exit_idhex+" has result "+str(result))
          plog("INFO", test.proto+" attempts: "+str(test.tests_run)+".  Completed: "+str(test.total_nodes - test.scan_nodes)+"/"+str(test.total_nodes)+" ("+str(test.percent_complete())+"%)")
        else:
          plog("INFO", "No available exits for "+test.proto+" test.")
          continue

    # Check each test for rewind
    all_finished = True
    for test in tests.itervalues():
      if not test.finished():
        all_finished = False
      else:
        plog("NOTICE", test.proto+" test has finished all nodes.")
        datahandler.saveTest(test)
        if not fixed_exits:
          test.remove_false_positives()
        else:
          plog("NOTICE", "Not removing false positives for fixed-exit scan")
        if not do_rescan and rescan_at_finish:
          if not test.toggle_rescan():
            # Only timestamp as finished after the rescan
            test.timestamp_results(time.time())
          test.rewind()
          all_finished = False
        elif restart_at_finish:
          test.timestamp_results(time.time())
          test.rewind()
          all_finished = False
        else:
          test.timestamp_results(time.time())
    if all_finished:
      plog("NOTICE", "All tests have finished. Exiting\n")
      return
    if not any_avail:
      plog("NOTICE", "Not enough exits were available to complete the tests. Exiting")
      return

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
