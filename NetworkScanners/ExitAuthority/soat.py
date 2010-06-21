#!/usr/bin/python
#
# 2008 Aleksei Gorny, mentored by Mike Perry
# 2009 Mike Perry

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
import os
import random
import re
import sha
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

import Queue
import StringIO

from OpenSSL import SSL, crypto

if sys.version_info < (2, 5):
    from sets import Set as set

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
from soat_config_real import *

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

class ExitScanHandler(ScanSupport.ScanHandler):
  def __init__(self, c, selmgr, strm_selector):
    ScanSupport.ScanHandler.__init__(self, c, selmgr,
                                     strm_selector=strm_selector)
    self.rlock = threading.Lock()
    self.new_nodes=True

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
      restriction = NodeRestrictionList([FlagsRestriction(["Running", "Valid",
"Fast"]), MinBWRestriction(min_node_bw), ExitPolicyRestriction('255.255.255.255', port)])
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

  # FIXME: Hrmm is this in the right place?
  def check_all_exits_port_consistency(self):
    '''
    an independent test that finds nodes that allow connections over a
    common protocol while disallowing connections over its secure version
    (for instance http/https)
    '''

    # get the structure
    routers = self.c.read_routers(self.c.get_network_status())
    bad_exits = set([])
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




# Http request handling
def http_request(address, cookie_jar=None, headers=firefox_headers):
  ''' perform a http GET-request and return the content received '''
  request = urllib2.Request(address)
  for h in headers:
    request.add_header(h[0], h[1])

  content = ""
  new_cookies = []
  mime_type = ""
  try:
    plog("DEBUG", "Starting request for: "+address)
    if cookie_jar != None:
      opener = urllib2.build_opener(NoDNSHTTPHandler, urllib2.HTTPCookieProcessor(cookie_jar))
      reply = opener.open(request)
      if "__filename" in cookie_jar.__dict__:
        cookie_jar.save(cookie_jar.__filename, ignore_discard=True)
      new_cookies = cookie_jar.make_cookies(reply, request)
    else:
      reply = urllib2.urlopen(request)

    length = reply.info().get("Content-Length")
    if length and int(length) > max_content_size:
      plog("WARN", "Max content size exceeded for "+address+": "+length)
      return (reply.code, None, [], "", "")
    mime_type = reply.info().type.lower()
    reply_headers = HeaderDiffer.filter_headers(reply.info().items())
    reply_headers.add(("mime-type", mime_type))
    plog("DEBUG", "Mime type is "+mime_type+", length "+str(length))
    content = decompress_response_data(reply)
  except socket.timeout, e:
    plog("WARN", "Socket timeout for "+address+": "+str(e))
    traceback.print_exc()
    return (-6.0, None, [], "", e.__class__.__name__+str(e))
  except httplib.BadStatusLine, e:
    plog('NOTICE', "HTTP Error during request of "+address+": "+str(e))
    if not e.line: 
      return (-13.0, None, [], "", e.__class__.__name__+"(None)") 
    else:
      traceback.print_exc()
      return (-666.0, None, [], "", e.__class__.__name__+str(e)) 
  except urllib2.HTTPError, e:
    plog('NOTICE', "HTTP Error during request of "+address+": "+str(e))
    if str(e) == "<urlopen error timed out>": # Yah, super ghetto...
      return (-6.0, None, [], "", e.__class__.__name__+str(e)) 
    else:
      traceback.print_exc()
      return (e.code, None, [], "", e.__class__.__name__+str(e)) 
  except (ValueError, urllib2.URLError), e:
    plog('WARN', 'The http-request address ' + address + ' is malformed')
    if str(e) == "<urlopen error timed out>": # Yah, super ghetto...
      return (-6.0, None, [], "", e.__class__.__name__+str(e)) 
    else:
      traceback.print_exc()
      return (-23.0, None, [], "", e.__class__.__name__+str(e))
  except socks.Socks5Error, e:
    plog('WARN', 'A SOCKS5 error '+str(e.value[0])+' occured for '+address+": "+str(e))
    return (-float(e.value[0]), None, [], "", e.__class__.__name__+str(e))
  except KeyboardInterrupt:
    raise KeyboardInterrupt
  except Exception, e:
    plog('WARN', 'An unknown HTTP error occured for '+address+": "+str(e))
    traceback.print_exc()
    return (-666.0, None, [], "", e.__class__.__name__+str(e))

  return (reply.code, reply_headers, new_cookies, mime_type, content)

class Test:
  """ Base class for our tests """
  def __init__(self, proto, port):
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
    self._pickle_revision = 6 # Will increment as fields are added

  def run_test(self): 
    raise NotImplemented()

  def get_targets(self): 
    raise NotImplemented()

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

  def refill_targets(self):
    if len(self.targets) < self.min_targets:
      plog("NOTICE", self.proto+" scanner short on targets. Adding more")
      self.targets.extend(self.get_targets())

  def _remove_target_addr(self, target):
    if target in self.targets:
      self.targets.remove(target)

  def remove_target(self, target, reason="None"):
    self.banned_targets.add(target)
    self.refill_targets()
    self._remove_target_addr(target)
    if target in self.dynamic_fails:
      del self.dynamic_fails[target]
    if target in self.successes:
      del self.successes[target]
    if target in self.exit_fails:
      del self.exit_fails[target]
    if target in self.connect_fails:
      del self.connect_fails[target]
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

  def load_rescan(self, type, since=None):
    self.rescan_nodes = set([])
    results = datahandler.getAll()
    for r in results:
      if r.status == type:
        if not since or r.timestamp >= since:
          self.rescan_nodes.add(r.exit_node[1:])
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
    else:
      plog("NOTICE", self.proto+" switching to recan mode.")
      self.load_rescan(TEST_FAILURE, self.run_start)

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
    for r in self.results:
      if not r.confirmed and not r.false_positive and r.status == TEST_FAILURE:
        r.confirmed=True # only save confirmed stuff once.
        datahandler.saveResult(r)

  def _reset(self):
    self.results = []
    self.targets = []
    self.tests_run = 0
    self.nodes_marked = 0
    self.run_start = time.time()
    # These are indexed by idhex
    self.connect_fails_per_exit = {}
    self.timeout_fails_per_exit = {}
    self.dns_fails_per_exit = {}
    self.node_results = {}
    # These are indexed by site url:
    self.connect_fails = {}
    self.exit_fails = {}
    self.successes = {}
    self.dynamic_fails = {}
 
  def rewind(self):
    self._reset()
    self.update_nodes()
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
    return tot_cnt

  def register_success(self, result):
    if self.rescan_nodes:
      result.from_rescan = True
    #datahandler.saveResult(result)
    if result.site in self.successes: 
      self.successes[result.site].add(result.exit_node)
    else:
      self.successes[result.site]=set([result.exit_node])

    win_cnt = len(self.successes[result.site])
    
    plog("INFO", self.proto+" success at "+result.exit_node+". This makes "+str(win_cnt)+"/"+str(self.site_tests(result.site))+" node successes for "+result.site)

  def _register_site_connect_failure(self, result): 
    if self.rescan_nodes:
      result.from_rescan = True
    self.results.append(result)
    datahandler.saveResult(result)
    if result.site in self.connect_fails:
      self.connect_fails[result.site].add(result.exit_node)
    else:
      self.connect_fails[result.site] = set([result.exit_node])
    
    err_cnt = len(self.connect_fails[result.site])

    plog("ERROR", self.proto+" connection fail of "+result.reason+" at "+result.exit_node+". This makes "+str(err_cnt)+"/"+str(self.site_tests(result.site))+" node failures for "+result.site)

  def register_connect_failure(self, result):
    if self.rescan_nodes:
      result.from_rescan = True
    if result.exit_node not in self.connect_fails_per_exit:
      self.connect_fails_per_exit[result.exit_node] = 0
    self.connect_fails_per_exit[result.exit_node] += 1

    c_cnt = self.connect_fails_per_exit[result.exit_node]
   
    if c_cnt > num_connfails_per_node:
      if result.extra_info:
        result.extra_info = str(result.extra_info) + " count: "+str(c_cnt)
      else: 
        result.extra_info = str(c_cnt)
      self._register_site_connect_failure(result)
      del self.connect_fails_per_exit[result.exit_node]
      return TEST_FAILURE
    else:
      plog("NOTICE", self.proto+" connect fail at "+result.exit_node+". This makes "+str(c_cnt)+" fails")
      return TEST_INCONCLUSIVE

  def register_dns_failure(self, result):
    if self.rescan_nodes:
      result.from_rescan = True
    if result.exit_node not in self.dns_fails_per_exit:
      self.dns_fails_per_exit[result.exit_node] = 0
    self.dns_fails_per_exit[result.exit_node] += 1

    d_cnt = self.dns_fails_per_exit[result.exit_node]
   
    if d_cnt > num_dnsfails_per_node:
      if result.extra_info:
        result.extra_info = str(result.extra_info) + " count: "+str(d_cnt)
      else: 
        result.extra_info = str(d_cnt)
      self._register_site_connect_failure(result)
      del self.dns_fails_per_exit[result.exit_node]
      return TEST_FAILURE
    else:
      plog("NOTICE", self.proto+" dns fail at "+result.exit_node+". This makes "+str(d_cnt)+" fails")
      return TEST_INCONCLUSIVE

  def register_timeout_failure(self, result):
    if self.rescan_nodes:
      result.from_rescan = True
    if result.exit_node not in self.timeout_fails_per_exit:
      self.timeout_fails_per_exit[result.exit_node] = 0
    self.timeout_fails_per_exit[result.exit_node] += 1

    t_cnt = self.timeout_fails_per_exit[result.exit_node]
   
    if t_cnt > num_timeouts_per_node:
      if result.extra_info:
        result.extra_info = str(result.extra_info) + " count: "+str(t_cnt)
      else: 
        result.extra_info = str(t_cnt)
      self._register_site_connect_failure(result)
      del self.timeout_fails_per_exit[result.exit_node]
      return TEST_FAILURE
    else:
      plog("NOTICE", self.proto+" timeout at "+result.exit_node+". This makes "+str(t_cnt)+" timeouts")
      return TEST_INCONCLUSIVE

  def register_exit_failure(self, result):
    if self.rescan_nodes:
      result.from_rescan = True
    datahandler.saveResult(result)
    self.results.append(result)

    if result.site in self.exit_fails: 
      self.exit_fails[result.site].add(result.exit_node)
    else:
      self.exit_fails[result.site] = set([result.exit_node])

    err_cnt = len(self.exit_fails[result.site])

    plog("ERROR", self.proto+" exit-only fail of "+result.reason+" at "+result.exit_node+". This makes "+str(err_cnt)+"/"+str(self.site_tests(result.site))+" node failures for "+result.site)

  def register_dynamic_failure(self, result):
    if self.rescan_nodes:
      result.from_rescan = True
    self.results.append(result)
    datahandler.saveResult(result)
    if result.site in self.dynamic_fails:
      self.dynamic_fails[result.site].add(result.exit_node)
    else:
      self.dynamic_fails[result.site] = set([result.exit_node])

    err_cnt = len(self.dynamic_fails[result.site])

    plog("ERROR", self.proto+" dynamic fail of "+result.reason+" at "+result.exit_node+". This makes "+str(err_cnt)+"/"+str(self.site_tests(result.site))+" node failures for "+result.site)


class SearchBasedTest(Test):
  def __init__(self, proto, port, wordlist_file):
    self.wordlist_file = wordlist_file
    Test.__init__(self, proto, port)

  def rewind(self):
    self.wordlist = load_wordlist(self.wordlist_file)
    Test.rewind(self)

  def _is_useable_url(self, url, valid_schemes=None, filetypes=None):
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
    if filetypes: # Must be checked last
      for filetype in filetypes:
        if url[-len(filetype):] == filetype:
          return True
      plog("DEBUG", "Bad filetype for "+url)
      return False
    return True

  def get_search_urls(self, protocol='any', results_per_type=10, host_only=False, filetypes=['any'], search_mode=default_search_mode):
    ''' 
    construct a list of urls based on the wordlist, filetypes and protocol. 
    '''
    plog('INFO', 'Searching google for relevant sites...')
  
    urllist = set([])
    for filetype in filetypes:
      type_urls = set([])
  
      while len(type_urls) < results_per_type:
        query = random.choice(self.wordlist)
        if filetype != 'any':
          query += " "+search_mode["filetype"]+filetype
        if protocol != 'any' and search_mode["inurl"]:
          query += " "+search_mode["inurl"]+protocol # this isn't too reliable, but we'll re-filter results later
        #query += '&num=' + `g_results_per_page` 
  
        # search google for relevant pages
        # note: google only accepts requests from idenitified browsers
        host = search_mode["host"]
        params = urllib.urlencode({search_mode["query"] : query})
        search_path = '/search' + '?' + params
        search_url = "http://"+host+search_path
         
        plog("INFO", "Search url: "+search_url)
        try:
          if search_mode["useragent"]:
            (code, resp_headers, new_cookies, mime_type, content) = http_request(search_url, search_cookies)
          else:
            headers = filter(lambda h: h[0] != "User-Agent", 
                             copy.copy(firefox_headers))
            (code, resp_headers, new_cookies, mime_type, content) = http_request(search_url, search_cookies, headers)
        except socket.gaierror:
          plog('ERROR', 'Scraping of http://'+host+search_path+" failed")
          traceback.print_exc()
          return list(urllist)
        except:
          plog('ERROR', 'Scraping of http://'+host+search_path+" failed")
          traceback.print_exc()
          # Bloody hack just to run some tests overnight
          return [protocol+"://www.eff.org", protocol+"://www.fastmail.fm", protocol+"://www.torproject.org", protocol+"://secure.wikileaks.org/"]
  
        links = SoupStrainer('a')
        try:
          soup = TheChosenSoup(content, parseOnlyThese=links)
        except Exception:
          plog('ERROR', 'Soup-scraping of http://'+host+search_path+" failed")
          traceback.print_exc()
          print "Content is: "+str(content)
          return [protocol+"://www.eff.org", protocol+"://www.fastmail.fm", protocol+"://www.torproject.org", protocol+"://secure.wikileaks.org/"] 
        # get the links and do some additional filtering
        for link in soup.findAll('a'):
          skip = True
          for a in link.attrs:
            if a[0] == "class" and search_mode["class"] in a[1]:
              skip = False
              break
          if skip:
            continue
          if link.has_key(search_mode['realtgt']):
            url = link[search_mode['realtgt']]
          else:
            url = link['href']
          if protocol == 'any':
            prot_list = None
          else:
            prot_list = [protocol]
          if filetype == 'any':
            file_list = None
          else:
            file_list = filetypes

          if self._is_useable_url(url, prot_list, file_list):
            if host_only:
              # FIXME: %-encoding, @'s, etc?
              host = urlparse.urlparse(url)[1]
              # Have to check again here after parsing the url: 
              if host not in self.banned_targets:
                type_urls.add(host)
            else:
              type_urls.add(url)
          else:
            pass
        plog("INFO", "Have "+str(len(type_urls))+"/"+str(results_per_type)+" google urls so far..") 

      # make sure we don't get more urls than needed
      if len(type_urls) > results_per_type:
        type_urls = set(random.sample(type_urls, results_per_type))
      urllist.update(type_urls)
       
    return list(urllist)

class HTTPTest(SearchBasedTest):
  def __init__(self, wordlist, filetypes=scan_filetypes):
    # FIXME: Handle http urls w/ non-80 ports..
    SearchBasedTest.__init__(self, "HTTP", 80, wordlist)
    self.fetch_targets = urls_per_filetype
    self.httpcode_fails = {}
    self.scan_filetypes = filetypes

  def _reset(self):
    SearchBasedTest._reset(self)
    self.targets = {}

  def rewind(self):
    SearchBasedTest.rewind(self)
    self.httpcode_fails = {}

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
    self.headers = copy.copy(firefox_headers)
   
    self.tests_run += 1

    n_tests = random.choice(xrange(1,len(self.targets)+1))
    filetypes = random.sample(self.targets.keys(), n_tests)
    
    plog("INFO", "HTTPTest decided to fetch "+str(n_tests)+" urls of types: "+str(filetypes))

    n_success = n_fail = n_inconclusive = 0 
    for ftype in filetypes:
      # FIXME: Set referrer to random or none for each of these
      address = random.choice(self.targets[ftype])
      result = self.check_http(address)
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

  def _remove_target_addr(self, target):
    for ftype in self.targets:
      if target in self.targets[ftype]:
        self.targets[ftype].remove(target)

  def remove_target(self, address, reason):
    SearchBasedTest.remove_target(self, address, reason)
    if address in self.httpcode_fails:
      del self.httpcode_fails[address]

  def refill_targets(self):
    for ftype in self.targets:
      if len(self.targets[ftype]) < self.fetch_targets:
        plog("NOTICE", self.proto+" scanner short on "+ftype+" targets. Adding more")
        raw_urls = self.get_search_urls('http', self.fetch_targets, 
                                        filetypes=[ftype])
        self.targets[ftype].extend(raw_urls)

    
  def get_targets(self):
    raw_urls = self.get_search_urls('http', self.fetch_targets, 
                                     filetypes=self.scan_filetypes)
    urls = {} 
    # Slow, but meh..
    for ftype in self.scan_filetypes: urls[ftype] = []
    for url in raw_urls:
      for ftype in self.scan_filetypes:
        if url[-len(ftype):] == ftype:
          urls[ftype].append(url)
    return urls     

  def remove_false_positives(self):
    SearchBasedTest.remove_false_positives(self)
    self._remove_false_positive_type(self.httpcode_fails,
                                     FALSEPOSITIVE_HTTPERRORS,
                                     max_httpcode_fail_pct)
  def site_tests(self, site):
    tot_cnt = SearchBasedTest.site_tests(self, site) 
    if site in self.httpcode_fails:
      tot_cnt += len(self.httpcode_fails[site])
    return tot_cnt
    
  def register_http_failure(self, result): # XXX: Currently deadcode
    if self.rescan_nodes:
      result.from_rescan = True
    self.results.append(result)
    datahandler.saveResult(result)
    if result.site in self.httpcode_fails:
      self.httpcode_fails[result.site].add(result.exit_node)
    else:
      self.httpcode_fails[result.site] = set([result.exit_node])
    
    err_cnt = len(self.httpcode_fails[result.site])

    plog("ERROR", self.proto+" http error code fail of "+result.reason+" at "+result.exit_node+". This makes "+str(err_cnt)+"/"+str(self.site_tests(result.site))+" node failures for "+result.site)
    

  def check_http_nodynamic(self, address, nocontent=False):
    # TODO: use nocontent to cause us to not load content into memory.
    # This will require refactoring http_response though.
    ''' check whether a http connection to a given address is molested '''

    # an address representation acceptable for a filename 
    address_file = DataHandler.safeFilename(address[7:])
    content_prefix = http_content_dir+address_file
    
    # Keep a copy of the cookie jar before mods for refetch or
    # to restore on errors that cancel a fetch
    orig_cookie_jar = cookielib.MozillaCookieJar()
    for cookie in self.cookie_jar: orig_cookie_jar.set_cookie(cookie)
    orig_tor_cookie_jar = cookielib.MozillaCookieJar()
    for cookie in self.tor_cookie_jar: orig_tor_cookie_jar.set_cookie(cookie)

    try:
      # Load content from disk, md5
      content_file = open(content_prefix+'.content', 'r')
      sha1sum = sha.sha()
      buf = content_file.read(4096)
      while buf:
        sha1sum.update(buf)
        buf = content_file.read(4096)
      content_file.close()
      
      added_cookie_jar = cookielib.MozillaCookieJar()
      added_cookie_jar.load(content_prefix+'.cookies', ignore_discard=True)
      self.cookie_jar.load(content_prefix+'.cookies', ignore_discard=True)

      headerdiffer = SnakePickler.load(content_prefix+'.headerdiff')

      content = None
      mime_type = None 

    except IOError:
      (code, resp_headers, new_cookies, mime_type, content) = http_request(address, self.cookie_jar, self.headers)

      if code - (code % 100) != 200:
        plog("NOTICE", "Non-tor HTTP error "+str(code)+" fetching content for "+address)
        # Just remove it
        self.remove_target(address, FALSEPOSITIVE_HTTPERRORS)
        # Restore cookie jars
        self.cookie_jar = orig_cookie_jar
        self.tor_cookie_jar = orig_tor_cookie_jar
        return TEST_INCONCLUSIVE

      if not content:
        plog("WARN", "Failed to direct load "+address)
        # Just remove it
        self.remove_target(address, INCONCLUSIVE_NOLOCALCONTENT)
        # Restore cookie jar
        self.cookie_jar = orig_cookie_jar
        self.tor_cookie_jar = orig_tor_cookie_jar
        return TEST_INCONCLUSIVE 
      sha1sum = sha.sha(content)

      content_file = open(content_prefix+'.content', 'w')
      content_file.write(content)
      content_file.close()
      
      headerdiffer = HeaderDiffer(resp_headers)
      SnakePickler.dump(headerdiffer, content_prefix+'.headerdiff')
      
      # Need to do set subtraction and only save new cookies.. 
      # or extract/make_cookies
      added_cookie_jar = cookielib.MozillaCookieJar()
      for cookie in new_cookies: added_cookie_jar.set_cookie(cookie)
      try:
        added_cookie_jar.save(content_prefix+'.cookies', ignore_discard=True)
      except:
        traceback.print_exc()
        plog("WARN", "Error saving cookies in "+str(self.cookie_jar)+" to "+content_prefix+".cookies")

    except TypeError, e:
      plog('ERROR', 'Failed obtaining the shasum for ' + address)
      plog('ERROR', e)
      # Restore cookie jars
      self.cookie_jar = orig_cookie_jar
      self.tor_cookie_jar = orig_tor_cookie_jar
      return TEST_INCONCLUSIVE

    defaultsocket = socket.socket
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TorUtil.tor_host,
                          TorUtil.tor_port)
    socket.socket = socks.socksocket

    (pcode, presp_headers, pnew_cookies, pmime_type, pcontent) = http_request(address, self.tor_cookie_jar, self.headers)
    psha1sum = sha.sha(pcontent)

    # reset the connection to direct
    PathSupport.SmartSocket.clear_port_table()
    socket.socket = defaultsocket

    exit_node = scanhdlr.get_exit_node()
    if not exit_node:
      plog('NOTICE', 'We had no exit node to test, skipping to the next test.')
      result = HttpTestResult(None, 
                              address, TEST_INCONCLUSIVE, INCONCLUSIVE_NOEXIT)
      if self.rescan_nodes:
        result.from_rescan = True
      self.results.append(result)
      datahandler.saveResult(result)

      # Restore cookie jars
      self.cookie_jar = orig_cookie_jar
      self.tor_cookie_jar = orig_tor_cookie_jar
      return TEST_INCONCLUSIVE

    exit_node = "$"+exit_node.idhex
    if pcode - (pcode % 100) != 200:
      plog("NOTICE", exit_node+" had error "+str(pcode)+" fetching content for "+address)
      # Restore cookie jars
      # XXX: This is odd and possibly wrong for the refetch
      self.cookie_jar = orig_cookie_jar
      self.tor_cookie_jar = orig_tor_cookie_jar
      BindingSocket.bind_to = refetch_ip
      (code_new, resp_headers_new, new_cookies_new, mime_type_new, content_new) = http_request(address, orig_tor_cookie_jar, self.headers)
      BindingSocket.bind_to = None
      
      if code_new == pcode:
        plog("NOTICE", "Non-tor HTTP error "+str(code_new)+" fetching content for "+address)
        # Just remove it
        self.remove_target(address, FALSEPOSITIVE_HTTPERRORS)
        return TEST_INCONCLUSIVE 

      if pcode < 0 and type(pcode) == float:
        if pcode == -1: # "General socks error"
          fail_reason = FAILURE_CONNERROR
        elif pcode == -2: # "connection not allowed aka ExitPolicy
          fail_reason = FAILURE_EXITPOLICY
        elif pcode == -3: # "Net Unreach" ??
          fail_reason = FAILURE_NETUNREACH
        elif pcode == -4: # "Host Unreach" aka RESOLVEFAILED
          fail_reason = FAILURE_HOSTUNREACH
          result = HttpTestResult(self.node_map[exit_node[1:]],
                                 address, TEST_FAILURE, fail_reason)
          return self.register_dns_failure(result)
        elif pcode == -5: # Connection refused
          fail_reason = FAILURE_CONNREFUSED
          result = HttpTestResult(self.node_map[exit_node[1:]], 
                              address, TEST_FAILURE, fail_reason)
          self.register_exit_failure(result)
          return TEST_FAILURE
        elif pcode == -6: # timeout
          fail_reason = FAILURE_TIMEOUT
          result = HttpTestResult(self.node_map[exit_node[1:]],
                                 address, TEST_FAILURE, fail_reason)
          return self.register_timeout_failure(result)
        elif pcode == -13:
          fail_reason = FAILURE_NOEXITCONTENT
          result = HttpTestResult(self.node_map[exit_node[1:]], 
                              address, TEST_FAILURE, fail_reason)
          self.register_exit_failure(result)
          return TEST_FAILURE
        elif pcode == -23: 
          fail_reason = FAILURE_URLERROR
        else:
          fail_reason = FAILURE_MISCEXCEPTION
      else: 
        fail_reason = FAILURE_BADHTTPCODE+str(pcode)
      result = HttpTestResult(self.node_map[exit_node[1:]], 
                            address, TEST_FAILURE, fail_reason)
      result.extra_info = str(pcontent)
      self.register_connect_failure(result)
      return TEST_FAILURE

    # if we have no content, we had a connection error
    if pcontent == "":
      result = HttpTestResult(self.node_map[exit_node[1:]], 
                              address, TEST_FAILURE, FAILURE_NOEXITCONTENT)
      self.register_exit_failure(result)
      # Restore cookie jars
      self.cookie_jar = orig_cookie_jar
      self.tor_cookie_jar = orig_tor_cookie_jar
      return TEST_FAILURE

    hdiffs = headerdiffer.show_differences(presp_headers)
    if hdiffs:
      plog("NOTICE", "Header differences for "+address+": \n"+hdiffs)

    # compare the content
    # if content matches, everything is ok
    if not hdiffs and psha1sum.hexdigest() == sha1sum.hexdigest():
      result = HttpTestResult(self.node_map[exit_node[1:]], 
                              address, TEST_SUCCESS)
      self.register_success(result)
      return TEST_SUCCESS

    # Check for a simple truncation failure, which seems
    # common with many nodes
    if not content and not nocontent:
      load_file = content_prefix+'.content'
      content_file = open(load_file, 'r')
      content = content_file.read()
      content_file.close()
    
    if content and len(pcontent) < len(content):
      if content[0:len(pcontent)] == pcontent[0:len(pcontent)]:
        failed_prefix = http_failed_dir+address_file
        exit_content_file = open(DataHandler.uniqueFilename(failed_prefix+'.'+exit_node[1:]+'.content'), 'w')
        exit_content_file.write(pcontent)
        exit_content_file.close()
        result = HttpTestResult(self.node_map[exit_node[1:]], 
                                address, TEST_FAILURE, FAILURE_EXITTRUNCATION, 
                                sha1sum.hexdigest(), psha1sum.hexdigest(), 
                                content_prefix+".content",
                                exit_content_file.name)
        self.register_exit_failure(result)
        # Restore cookie jars
        self.cookie_jar = orig_cookie_jar
        self.tor_cookie_jar = orig_tor_cookie_jar
        return TEST_FAILURE

    # if content doesnt match, update the direct content and use new cookies
    # If we have alternate IPs to bind to on this box, use them?
    # Sometimes pages have the client IP encoded in them..
    # Also, use the Tor cookies, since those identifiers are
    # probably embeded in the Tor page as well.
    BindingSocket.bind_to = refetch_ip
    (code_new, resp_headers_new, new_cookies_new, mime_type_new, content_new) = http_request(address, orig_tor_cookie_jar, self.headers)
    BindingSocket.bind_to = None
    
    if not content_new:
      plog("WARN", "Failed to re-frech "+address+" outside of Tor. Did our network fail?")
      result = HttpTestResult(self.node_map[exit_node[1:]], 
                              address, TEST_INCONCLUSIVE, 
                              INCONCLUSIVE_NOLOCALCONTENT)
      if self.rescan_nodes:
        result.from_rescan = True
      self.results.append(result)
      datahandler.saveResult(result)
      return TEST_INCONCLUSIVE

    headerdiffer.prune_differences(resp_headers_new)
    hdiffs = headerdiffer.show_differences(presp_headers)

    SnakePickler.dump(headerdiffer, content_prefix+'.headerdiff')

    sha1sum_new = sha.sha(content_new)

    if sha1sum.hexdigest() != sha1sum_new.hexdigest():
      # if content has changed outside of tor, update the saved file
      os.rename(content_prefix+'.content', content_prefix+'.content-old')
      new_content_file = open(content_prefix+'.content', 'w')
      new_content_file.write(content_new)
      new_content_file.close()

    # Need to do set subtraction and only save new cookies.. 
    # or extract/make_cookies
    
    self.cookie_jar = orig_cookie_jar
    new_cookie_jar = cookielib.MozillaCookieJar()
    for cookie in new_cookies_new: 
      new_cookie_jar.set_cookie(cookie)
      self.cookie_jar.set_cookie(cookie) # Update..
    os.rename(content_prefix+'.cookies', content_prefix+'.cookies-old')
    try:
      new_cookie_jar.save(content_prefix+'.cookies', ignore_discard=True)
    except:
      traceback.print_exc()
      plog("WARN", "Error saving cookies in "+str(new_cookie_jar)+" to "+content_prefix+".cookies")

    if hdiffs:
      # XXX: We probably should store the header differ + exit headers 
      # for later comparison (ie if the header differ picks up more diffs)
      plog("NOTICE", "Post-refetch header changes for "+address+": \n"+hdiffs)
      result = HttpTestResult(self.node_map[exit_node[1:]], 
                              address, TEST_FAILURE, FAILURE_HEADERCHANGE)
      result.extra_info = hdiffs
      self.register_dynamic_failure(result)
      # Lets let the rest of the tests run too actually
      #return TEST_FAILURE 

    # compare the node content and the new content
    # if it matches, everything is ok
    if psha1sum.hexdigest() == sha1sum_new.hexdigest():
      result = HttpTestResult(self.node_map[exit_node[1:]], 
                              address, TEST_SUCCESS)
      self.register_success(result)
      return TEST_SUCCESS
 
    if not content and not nocontent:
      if sha1sum.hexdigest() != sha1sum_new.hexdigest():
        load_file = content_prefix+'.content-old'
      else:
        load_file = content_prefix+'.content'
      content_file = open(load_file, 'r')
      content = content_file.read()
      content_file.close()
    
    if not ((mime_type == mime_type_new or not mime_type) \
               and mime_type_new == pmime_type):
      if not mime_type:
        mime_type = "text/disk"
      plog("WARN", "Mime type change: 1st: "+mime_type+", 2nd: "+mime_type_new+", Tor: "+pmime_type)
      # TODO: If this actually happens, store a result.

    # Dirty dirty dirty...
    return (mime_type_new, pcontent, psha1sum, content, sha1sum, content_new, 
            sha1sum_new, exit_node)

  def check_http(self, address):
    plog('INFO', 'Conducting an http test with destination ' + address)
    ret = self.check_http_nodynamic(address)
    if type(ret) == int:
      return ret
    return self._check_http_worker(address, ret) 

  def _check_http_worker(self, address, http_ret):
    (mime_type,pcontent,psha1sum,content,sha1sum,content_new,sha1sum_new,exit_node) = http_ret
     
    address_file = DataHandler.safeFilename(address[7:])
    content_prefix = http_content_dir+address_file
    failed_prefix = http_failed_dir+address_file

    # compare the new and old content
    # if they match, means the node has been changing the content
    if sha1sum.hexdigest() == sha1sum_new.hexdigest():
      exit_content_file = open(DataHandler.uniqueFilename(failed_prefix+'.'+exit_node[1:]+'.content'), 'w')
      exit_content_file.write(pcontent)
      exit_content_file.close()

      result = HttpTestResult(self.node_map[exit_node[1:]],
                              address, TEST_FAILURE, FAILURE_EXITONLY, 
                              sha1sum.hexdigest(), psha1sum.hexdigest(), 
                              content_prefix+".content", exit_content_file.name)
      self.register_exit_failure(result)
      return TEST_FAILURE

    exit_content_file = open(DataHandler.uniqueFilename(failed_prefix+'.'+exit_node[1:]+'.dyn-content'),'w')
    exit_content_file.write(pcontent)
    exit_content_file.close()

    result = HttpTestResult(self.node_map[exit_node[1:]], 
                            address, TEST_FAILURE, FAILURE_DYNAMIC, 
                            sha1sum_new.hexdigest(), psha1sum.hexdigest(), 
                            content_prefix+".content", exit_content_file.name, 
                            content_prefix+'.content-old',
                            sha1sum.hexdigest())
    if self.rescan_nodes:
      result.from_rescan = True
    self.results.append(result)
    datahandler.saveResult(result)

    # The HTTP Test should remove address immediately...
    plog("WARN", "HTTP Test is removing dynamic URL "+address)
    self.remove_target(address, FALSEPOSITIVE_DYNAMIC)
    return TEST_FAILURE

class HTMLTest(HTTPTest):
  def __init__(self, wordlist, recurse_filetypes=scan_filetypes):
    HTTPTest.__init__(self, wordlist, recurse_filetypes)
    self.fetch_targets = num_html_urls
    self.proto = "HTML"
    self.recurse_filetypes = recurse_filetypes
    self.fetch_queue = []
   
  def _reset(self):
    HTTPTest._reset(self)
    self.targets = [] # FIXME: Lame..
    self.soupdiffer_files = {} # XXX: These two are now deprecated
    self.jsdiffer_files = {}
 
  def depickle_upgrade(self):
    if self._pickle_revision < 2:
      self.soupdiffer_files = {}
      self.jsdiffer_files = {}
    SearchBasedTest.depickle_upgrade(self)

  def run_test(self):
    # A single test should have a single cookie jar
    self.tor_cookie_jar = cookielib.MozillaCookieJar()
    self.cookie_jar = cookielib.MozillaCookieJar()
    self.headers = copy.copy(firefox_headers)

    use_referers = False
    first_referer = None    
    if random.randint(1,100) < referer_chance_pct:
      use_referers = True
      # FIXME: Hrmm.. May want to do this a bit better..
      first_referer = random.choice(self.targets)
      plog("INFO", "Chose random referer "+first_referer)
    
    self.tests_run += 1
    address = random.choice(self.targets)
    
    # Keep a trail log for this test and check for loops
    fetched = set([])

    self.fetch_queue.append(("html", address, first_referer))
    n_success = n_fail = n_inconclusive = 0 
    while self.fetch_queue:
      (test, url, referer) = self.fetch_queue.pop(0)
      if url in fetched:
        plog("INFO", "Already fetched "+url+", skipping")
        continue
      fetched.add(url)
      if use_referers and referer: 
        self.headers.append(('Referer', referer))
      # Technically both html and js tests check and dispatch via mime types
      # but I want to know when link tags lie
      if test == "html" or test == "http":
        result = self.check_html(url)
      elif test == "js":
        result = self.check_js(url)
      elif test == "image":
        accept_hdr = filter(lambda h: h[0] == "Accept", self.headers)[0]
        orig_accept = accept_hdr[1]
        accept_hdr[1] = image_accept_hdr
        result = self.check_http(url)
        accept_hdr[1] = orig_accept
      else: 
        plog("WARN", "Unknown test type: "+test+" for "+url)
        result = TEST_SUCCESS
      if result == TEST_INCONCLUSIVE:
        n_inconclusive += 1
      if result == TEST_FAILURE:
        n_fail += 1
      if result == TEST_SUCCESS:
        n_success += 1

    # Need to clear because the cookiejars use locks...
    self.tor_cookie_jar = None
    self.cookie_jar = None

    if n_fail:
      return TEST_FAILURE
    elif 2*n_inconclusive > n_success: # > 33% inconclusive -> redo
      return TEST_INCONCLUSIVE
    else:
      return TEST_SUCCESS 

  # FIXME: This is pretty lame.. We should change how
  # the HTTPTest stores URLs so we don't have to do this.
  def _remove_target_addr(self, target):
    Test._remove_target_addr(self, target)
    if target in self.soupdiffer_files:
      del self.soupdiffer_files[target]
    if target in self.jsdiffer_files:
      del self.jsdiffer_files[target]

  def refill_targets(self):
    Test.refill_targets(self)

  def get_targets(self):
    return self.get_search_urls('http', self.fetch_targets) 

  def _add_recursive_targets(self, soup, orig_addr):
    # Only pull at most one filetype from the list of 'a' links
    targets = []
    got_type = {}
    found_favicon = False
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
                  a = map(lambda x: x.lower(), a)
                  # Special case CSS and favicons
                  if (a[0] == "type" and a[1] == "text/css") or \
                   ((a[0] == "rel" or a[0] == "rev") and a[1] == "stylesheet"):
                    plog("INFO", "Adding CSS of: "+str(t))
                    targets.append(("http", urlparse.urljoin(orig_addr, attr_tgt)))
                  elif (a[0] == "rel" or a[0] == "rev") and \
                       ("shortcut" in a[1] or "icon" in a[1]):
                    plog("INFO", "Adding favicon of: "+str(t))
                    found_favicon = True
                    targets.append(("image", urlparse.urljoin(orig_addr, attr_tgt)))
                  elif a[0] == "type" and self.is_script(a[1], ""):
                    plog("INFO", "Adding link script of: "+str(t))
                    targets.append(("js", urlparse.urljoin(orig_addr, attr_tgt)))
              else:
                plog("INFO", "Adding script tag of: "+str(t))
                targets.append(("js", urlparse.urljoin(orig_addr, attr_tgt)))
            elif t.name in recurse_image:
              plog("INFO", "Adding image tag of: "+str(t))
              targets.append(("image", urlparse.urljoin(orig_addr, attr_tgt)))
            elif t.name == 'a':
              if attr_name == "href":
                for f in self.recurse_filetypes:
                  if f not in got_type and attr_tgt[-len(f):] == f:
                    got_type[f] = 1
                    targets.append(("http", urlparse.urljoin(orig_addr, attr_tgt)))
            else:
              targets.append(("http", urlparse.urljoin(orig_addr, attr_tgt)))
    
    if not found_favicon:
      targets.insert(0, ("image", urlparse.urljoin(orig_addr, "/favicon.ico")))

    loaded = set([])

    for i in targets:
      if i[1] in loaded:
        continue
      loaded.add(i[1])
      if self._is_useable_url(i[1], html_schemes):
        plog("NOTICE", "Adding "+i[0]+" target: "+i[1])
        self.fetch_queue.append((i[0], i[1], orig_addr))
      else:
        plog("NOTICE", "Skipping "+i[0]+" target: "+i[1])

  def check_js(self, address):
    plog('INFO', 'Conducting a js test with destination ' + address)

    accept_hdr = filter(lambda h: h[0] == "Accept", self.headers)[0]
    orig_accept = accept_hdr[1]
    accept_hdr[1] = script_accept_hdr
    ret = self.check_http_nodynamic(address)
    accept_hdr[1] = orig_accept

    if type(ret) == int:
      return ret
    return self._check_js_worker(address, ret)

  def is_html(self, mime_type, content):
    is_html = False
    for type_match in html_mime_types:
      if re.match(type_match, mime_type.lower()): 
        is_html = True
        break
    return is_html
 
  def is_script(self, mime_type, content):
    is_script = False
    for type_match in script_mime_types:
      if re.match(type_match, mime_type.lower()): 
        is_script = True
        break
    return is_script

  def _check_js_worker(self, address, http_ret):
    (mime_type, tor_js, tsha, orig_js, osha, new_js, nsha, exit_node) = http_ret

    if not self.is_script(mime_type, orig_js):
      plog("WARN", "Non-script mime type "+mime_type+" fed to JS test for "+address)
     
      if self.is_html(mime_type, orig_js):
        return self._check_html_worker(address, http_ret)
      else:
        return self._check_http_worker(address, http_ret)

    address_file = DataHandler.safeFilename(address[7:])
    content_prefix = http_content_dir+address_file
    failed_prefix = http_failed_dir+address_file

    if os.path.exists(content_prefix+".jsdiff"):
      plog("DEBUG", "Loading jsdiff for "+address)
      jsdiff = SnakePickler.load(content_prefix+".jsdiff")
    else:
      plog("DEBUG", "No jsdiff for "+address+". Creating+dumping")
      jsdiff = JSDiffer(orig_js)
    
    jsdiff.prune_differences(new_js)
    SnakePickler.dump(jsdiff, content_prefix+".jsdiff")

    has_js_changes = jsdiff.contains_differences(tor_js)

    if not has_js_changes:
      result = JsTestResult(self.node_map[exit_node[1:]], 
                            address, TEST_SUCCESS)
      self.register_success(result)
      return TEST_SUCCESS
    else:
      exit_content_file = open(DataHandler.uniqueFilename(failed_prefix+'.'+exit_node[1:]+'.dyn-content'), 'w')
      exit_content_file.write(tor_js)
      exit_content_file.close()

      result = JsTestResult(self.node_map[exit_node[1:]], 
                             address, TEST_FAILURE, FAILURE_DYNAMIC, 
                             content_prefix+".content", exit_content_file.name, 
                             content_prefix+'.content-old',
                             content_prefix+".jsdiff")
      self.register_dynamic_failure(result)
      return TEST_FAILURE

  def check_html(self, address):
    plog('INFO', 'Conducting an html test with destination ' + address)
    ret = self.check_http_nodynamic(address)
    
    if type(ret) == int:
      return ret

    return self._check_html_worker(address, ret)

  def _check_html_worker(self, address, http_ret):
    (mime_type,tor_html,tsha,orig_html,osha,new_html,nsha,exit_node)=http_ret

    if not self.is_html(mime_type, orig_html):
      # XXX: Keep an eye on this logline.
      plog("WARN", "Non-html mime type "+mime_type+" fed to HTML test for "+address)
      if self.is_script(mime_type, orig_html):
        return self._check_js_worker(address, http_ret)
      else:
        return self._check_http_worker(address, http_ret)

    # an address representation acceptable for a filename 
    address_file = DataHandler.safeFilename(address[7:])
    content_prefix = http_content_dir+address_file
    failed_prefix = http_failed_dir+address_file

    orig_soup = FullyStrainedSoup(orig_html.decode('ascii', 'ignore'))
    tor_soup = FullyStrainedSoup(tor_html.decode('ascii', 'ignore'))

    # Also find recursive urls
    recurse_elements = SoupStrainer(lambda name, attrs: 
        name in tags_to_recurse and 
       len(set(map(lambda a: a[0], attrs)).intersection(set(attrs_to_recurse))) > 0)
    self._add_recursive_targets(TheChosenSoup(tor_html.decode('ascii',
                                   'ignore'), recurse_elements), address) 

    # compare the content
    # if content matches, everything is ok
    if str(orig_soup) == str(tor_soup):
      plog("INFO", "Successful soup comparison after SHA1 fail for "+address+" via "+exit_node)
      result = HtmlTestResult(self.node_map[exit_node[1:]], 
                              address, TEST_SUCCESS)
      self.register_success(result)

      return TEST_SUCCESS

    content_new = new_html.decode('ascii', 'ignore')
    if not content_new:
      plog("WARN", "Failed to re-frech "+address+" outside of Tor. Did our network fail?")
      result = HtmlTestResult(self.node_map[exit_node[1:]], 
                              address, TEST_INCONCLUSIVE, 
                              INCONCLUSIVE_NOLOCALCONTENT)
      if self.rescan_nodes:
        result.from_rescan = True
      self.results.append(result)
      datahandler.saveResult(result)
      return TEST_INCONCLUSIVE

    new_soup = FullyStrainedSoup(content_new)

    # compare the new and old content
    # if they match, means the node has been changing the content
    if str(orig_soup) == str(new_soup):
      exit_content_file = open(DataHandler.uniqueFilename(failed_prefix+'.'+exit_node[1:]+'.content'), 'w')
      exit_content_file.write(tor_html)
      exit_content_file.close()

      result = HtmlTestResult(self.node_map[exit_node[1:]], 
                              address, TEST_FAILURE, FAILURE_EXITONLY, 
                              content_prefix+".content", exit_content_file.name)
      self.register_exit_failure(result)
      return TEST_FAILURE

    # Lets try getting just the tag differences
    # 1. Take difference between old and new tags both ways
    # 2. Make map of tags that change to their attributes
    # 3. Compare list of changed tags for tor vs new and
    #    see if any extra tags changed or if new attributes
    #    were added to additional tags
    if os.path.exists(content_prefix+".soupdiff"):
      plog("DEBUG", "Loading soupdiff for "+address)
      soupdiff = SnakePickler.load(content_prefix+".soupdiff")
      soupdiff.prune_differences(new_soup)
    else:
      plog("DEBUG", "No soupdiff for "+address+". Creating+dumping")
      soupdiff = SoupDiffer(orig_soup, new_soup)

    SnakePickler.dump(soupdiff, content_prefix+".soupdiff")
    
    more_tags = soupdiff.show_changed_tags(tor_soup)     
    more_attrs = soupdiff.show_changed_attrs(tor_soup)
    more_content = soupdiff.show_changed_content(tor_soup)

    # Verify all of our changed tags are present here 
    if more_tags or more_attrs or (more_content and not soupdiff.content_changed):
      false_positive = False
      plog("NOTICE", "SoupDiffer finds differences for "+address)
      plog("NOTICE", "New Tags:\n"+more_tags)
      plog("NOTICE", "New Attrs:\n"+more_attrs)
      if more_content and not soupdiff.content_changed:
        plog("NOTICE", "New Content:\n"+more_content)
    else:
      plog("INFO", "SoupDiffer predicts false_positive")
      false_positive = True

    if false_positive:
      if os.path.exists(content_prefix+".jsdiff"):
        plog("DEBUG", "Loading jsdiff for "+address)
        jsdiff = SnakePickler.load(content_prefix+".jsdiff")
      else:
        plog("DEBUG", "No jsdiff for "+address+". Creating+dumping")
        jsdiff = JSSoupDiffer(orig_soup)
      
      jsdiff.prune_differences(new_soup)
      SnakePickler.dump(jsdiff, content_prefix+".jsdiff")

      differences = jsdiff.show_differences(tor_soup)
      false_positive = not differences
      plog("INFO", "JSSoupDiffer predicts false_positive="+str(false_positive))
      if not false_positive:
        plog("NOTICE", "JSSoupDiffer finds differences: "+differences)

    if false_positive:
      plog("NOTICE", "False positive detected for dynamic change at "+address+" via "+exit_node)
      result = HtmlTestResult(self.node_map[exit_node[1:]], 
                              address, TEST_SUCCESS)
      self.register_success(result)
      return TEST_SUCCESS

    exit_content_file = open(DataHandler.uniqueFilename(failed_prefix+'.'+exit_node[1:]+'.dyn-content'),'w')
    exit_content_file.write(tor_html)
    exit_content_file.close()

    if os.path.exists(content_prefix+".jsdiff"):
      jsdiff_file = content_prefix+".jsdiff"
    else:
      jsdiff_file = None
    if os.path.exists(content_prefix+".soupdiff"):
      soupdiff_file = content_prefix+".soupdiff"
    else:
      soupdiff_file = None

    result = HtmlTestResult(self.node_map[exit_node[1:]], 
                            address, TEST_FAILURE, FAILURE_DYNAMIC, 
                            content_prefix+".content", exit_content_file.name, 
                            content_prefix+'.content-old',
                            soupdiff_file, jsdiff_file)
    self.register_dynamic_failure(result)
    return TEST_FAILURE


class SSLTest(SearchBasedTest):
  def __init__(self, wordlist):
    self.test_hosts = num_ssl_hosts
    SearchBasedTest.__init__(self, "SSL", 443, wordlist)

  def run_test(self):
    self.tests_run += 1
    return self.check_openssl(random.choice(self.targets))

  def get_targets(self):
    return self.get_search_urls('https', self.test_hosts, True, search_mode=google_search_mode)

  def _raise_timeout(self, signum, frame):
    raise socket.timeout("SSL connection timed out")

  def ssl_request(self, address):
    # The SIGALARM can be triggered outside of the try/except in
    # _ssl_request, so we need to catch socket.timeout here
    try:
      return self._ssl_request(address)
    except socket.timeout, e:
      return (-6.0, None, "Socket timeout")

  def _ssl_request(self, address, method='TLSv1_METHOD'):
    ''' initiate an ssl connection and return the server certificate '''
    address=str(address) # Unicode hostnames not supported..

    # specify the context
    ctx = SSL.Context(getattr(SSL,method))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(None)

    signal.signal(signal.SIGALRM, self._raise_timeout)
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
    except socket.timeout, e:
      rval = (-6.0, None, "Socket timeout")
    except socks.Socks5Error, e:
      plog('WARN', 'A SOCKS5 error '+str(e.value[0])+' occured for '+address+": "+str(e))
      rval = (-float(e.value[0]), None,  e.__class__.__name__+str(e))
    except crypto.Error, e:
      traceback.print_exc()
      rval = (-23.0, None, e.__class__.__name__+str(e))
    except (SSL.ZeroReturnError, SSL.WantReadError, SSL.WantWriteError, SSL.WantX509LookupError), e:
      # XXX: None of these are really "errors" per se
      traceback.print_exc()
      rval = (-666.0, None, e.__class__.__name__+str(e))
    except SSL.SysCallError, e:
      # Errors on the underlying socket will be caught here.
      if e[0] == -1: # unexpected eof
        # Might be an SSLv2 server, but it's unlikely, let's just call it a CONNERROR
        rval = (float(e[0]), None, e[1])
      else:
        traceback.print_exc()
        rval = (-666.0, None, e.__class__.__name__+str(e))
    except SSL.Error, e:
      signal.alarm(0) # Since we might recurse
      for (lib, func, reason) in e.message: # e.message is always list of 3-tuples
        if reason in ('wrong version number','sslv3 alert illegal parameter'):
          # Check if the server supports a different SSL version
          if method == 'TLSv1_METHOD':
            plog('DEBUG','Could not negotiate SSL handshake with %s, retrying with SSLv3_METHOD' % address)
            rval = self._ssl_request(address, 'SSLv3_METHOD')
            break
      else:
        plog('WARN', 'An unknown SSL error occured for '+address+': '+str(e))
        traceback.print_exc()
        rval = (-666.0, None,  e.__class__.__name__+str(e))
    except KeyboardInterrupt:
      signal.alarm(0)
      raise
    except Exception, e:
      plog('WARN', 'An unknown SSL error occured for '+address+': '+str(e))
      traceback.print_exc()
      rval = (-666.0, None,  e.__class__.__name__+str(e))
    signal.alarm(0)
    return rval

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
      (code, raw_cert, exc) = self.ssl_request(ip)
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

  def check_openssl(self, address):
    ''' check whether an https connection to a given address is molested '''
    plog('INFO', 'Conducting an ssl test with destination ' + address)

    # an address representation acceptable for a filename 
    address_file = DataHandler.safeFilename(address[8:])
    ssl_file_name = ssl_certs_dir + address_file + '.ssl'

    # load the original cert and compare
    # if we don't have the original cert yet, get it
    try:
      ssl_domain = SnakePickler.load(ssl_file_name)
    except IOError:
      ssl_domain = SSLDomain(address)

    check_ips = []
    # Make 3 resolution attempts
    for attempt in xrange(1,4):
      try:
        resolved = []
        resolved = socket.getaddrinfo(address, 443)
        break
      except socket.gaierror:
        plog("NOTICE", "Local resolution failure #"+str(attempt)+" for "+address)

    for res in resolved:
      if res[0] == socket.AF_INET and res[2] == socket.IPPROTO_TCP:
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
    defaultsocket = socket.socket
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TorUtil.tor_host,
                          TorUtil.tor_port)
    socket.socket = socks.socksocket

    (code, cert, exc) = self.ssl_request(address)

    # reset the connection method back to direct
    PathSupport.SmartSocket.clear_port_table()
    socket.socket = defaultsocket

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
      if code < 0 and type(code) == float:
        if code == -1: # "General socks error"
          fail_reason = FAILURE_CONNERROR
        elif code == -2: # "connection not allowed" aka ExitPolicy
          fail_reason = FAILURE_EXITPOLICY
        elif code == -3: # "Net Unreach" ??
          fail_reason = FAILURE_NETUNREACH
        elif code == -4: # "Host Unreach" aka RESOLVEFAILED
          fail_reason = FAILURE_HOSTUNREACH
          result = SSLTestResult(self.node_map[exit_node[1:]], address,
                                ssl_file_name, TEST_FAILURE, fail_reason)
          return self.register_dns_failure(result)
        elif code == -5: # Connection refused
          fail_reason = FAILURE_CONNREFUSED
          result = SSLTestResult(self.node_map[exit_node[1:]],
                       address, ssl_file_name, TEST_FAILURE, fail_reason)
          self.extra_info=exc
          self.register_exit_failure(result)
          return TEST_FAILURE
        elif code == -6: # timeout
          fail_reason = FAILURE_TIMEOUT
          result = SSLTestResult(self.node_map[exit_node[1:]], address,
                                ssl_file_name, TEST_FAILURE, fail_reason)
          return self.register_timeout_failure(result)
        elif code == -23:
          fail_reason = FAILURE_CRYPTOERROR
          result = SSLTestResult(self.node_map[exit_node[1:]],
                       address, ssl_file_name, TEST_FAILURE, fail_reason)
          self.extra_info=exc
          self.register_exit_failure(result)
          return TEST_FAILURE
        else:
          fail_reason = FAILURE_MISCEXCEPTION
      else:
          fail_reason = FAILURE_MISCEXCEPTION

      result = SSLTestResult(self.node_map[exit_node[1:]],
                             address, ssl_file_name, TEST_FAILURE, fail_reason)
      result.extra_info = exc
      self.register_connect_failure(result)
      return TEST_FAILURE

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

  start = 0
  data = ""
  while True:
    data_read = response.read(500) # Cells are 495 bytes..
    if not start:
      start = time.time()
    # TODO: if this doesn't work, check stream observer for 
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


class NoURLsFound(Exception):
  pass


def cleanup(c, l, f):
  plog("INFO", "Resetting __LeaveStreamsUnattached=0 and FetchUselessDescriptors="+f)
  try:
    c.set_option("__LeaveStreamsUnattached", l)
    c.set_option("FetchUselessDescriptors", f)
  except TorCtl.TorCtlClosed:
    pass

def setup_handler(out_dir, cookie_file):
  plog('INFO', 'Connecting to Tor at '+TorUtil.control_host+":"+str(TorUtil.control_port))
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((TorUtil.control_host,TorUtil.control_port))
  c = PathSupport.Connection(s)
  c.debug(file(out_dir+"/control.log", "w", buffering=0))
  c.authenticate_cookie(file(cookie_file, "r"))
  l = c.get_option("__LeaveStreamsUnattached")[0][1]
  h = ExitScanHandler(c, __selmgr, PathSupport.SmartSocket.StreamSelector)

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
    print '--pernode <n>'
    print '--resume [<n>]'
    print '--rescan [<n>]'
    print '--ssl'
    print '--http'
    print '--html'
#    print '--ssh (doesn\'t work yet)'
#    print '--smtp (~works)'
#    print '--pop (~works)'
#    print '--imap (~works)'
    print '--dnsrebind (use with one or more of above tests)'
    print '--policies'
    print '--exit <exit>'
    print ''
    return

  opts = ['ssl','rescan', 'pernode=', 'resume=', 'html','http','ssh','smtp','pop','imap','dns','dnsrebind','policies','exit=']
  flags, trailer = getopt.getopt(argv[1:], [], opts)

  # get specific test types
  do_resume = False
  do_rescan = ('--rescan','') in flags
  do_ssl = ('--ssl','') in flags
  do_http = ('--http','') in flags
  do_html = ('--html','') in flags
  #do_ssh = ('--ssh','') in flags
  #do_smtp = ('--smtp','') in flags
  #do_pop = ('--pop','') in flags
  #do_imap = ('--imap','') in flags
  do_dns_rebind = ('--dnsrebind','') in flags
  do_consistency = ('--policies','') in flags

  scan_exit=None
  for flag in flags:
    if flag[0] == "--exit":
      scan_exit = flag[1]
    if flag[0] == "--pernode":
      global num_tests_per_node
      num_tests_per_node = int(flag[1])
    if flag[0] == "--rescan" and flag[1]:
      global num_rescan_tests_per_node
      num_rescan_tests_per_node = int(flag[1])
    if flag[0] == "--resume":
      do_resume = True
      if flag[1]:
        resume_run=int(flag[1])
      else:
        resume_run=-1

  TorUtil.read_config(data_dir+"/torctl.cfg")

  plog("DEBUG", "Read tor config. Got Socks proxy: "+str(TorUtil.tor_port))

  # Make logs go to disk so resumes are less painful
  #TorUtil.logfile = open(log_file_name, "a")

  # initiate the connection to tor
  try:
    global scanhdlr
    (c,scanhdlr) = setup_handler(data_dir,
                                 data_dir+"tor/control_auth_cookie")
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
  if not (do_ssl or do_html or do_http):
    plog('INFO', 'Done.')
    return

  # Load the cookie jar
  global search_cookies
  search_cookies = cookielib.LWPCookieJar()
  if os.path.isfile(search_cookie_file):
    search_cookies.load(search_cookie_file, ignore_discard=True)
  search_cookies.__filename = search_cookie_file

  tests = {}

  if do_resume:
    plog("NOTICE", "Resuming previous SoaT run #"+str(resume_run))
    if do_ssl:
      tests["SSL"] = datahandler.loadTest("SSLTest", resume_run)

    if do_http:
      tests["HTTP"] = datahandler.loadTest("HTTPTest", resume_run)

    if do_html:
      tests["HTML"] = datahandler.loadTest("HTMLTest", resume_run)
  
  else:
    if do_ssl:
      tests["SSL"] = SSLTest(ssl_wordlist_file)

    if do_http:
      tests["HTTP"] = HTTPTest(filetype_wordlist_file)

    if do_html:
      tests["HTML"] = HTMLTest(html_wordlist_file)


  # maybe no tests could be initialized
  if not tests:
    plog('INFO', 'Done.')
    sys.exit(0)

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

  if scan_exit:
    plog("NOTICE", "Scanning only "+scan_exit)
    scanhdlr.set_exit_node(scan_exit)
    scanhdlr.new_exit()

    while 1:
      for test in tests.values():
        result = test.run_test()
        plog("INFO", test.proto+" test via "+scan_exit+" has result "+str(result))

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

    if common_nodes:
      current_exit_idhex = random.choice(list(common_nodes))
      plog("DEBUG", "Chose to run "+str(n_tests)+" tests via "+current_exit_idhex+" (tests share "+str(len(common_nodes))+" exit nodes)")

      scanhdlr.set_exit_node("$"+current_exit_idhex)
      scanhdlr.new_exit()
      for test in to_run:
        result = test.run_test()
        if result != TEST_INCONCLUSIVE:
          test.mark_chosen(current_exit_idhex, result)
        datahandler.saveTest(test)
        plog("INFO", test.proto+" test via "+current_exit_idhex+" has result "+str(result))
        plog("INFO", test.proto+" attempts: "+str(test.tests_run)+".  Completed: "+str(test.total_nodes - test.scan_nodes)+"/"+str(test.total_nodes)+" ("+str(test.percent_complete())+"%)")
    else:
      plog("NOTICE", "No nodes in common between "+", ".join(map(lambda t: t.proto, to_run)))
      for test in to_run:
        if test.finished():
          continue
        current_exit = test.get_node()
        scanhdlr.set_exit_node("$"+current_exit_idhex)
        scanhdlr.new_exit()
        result = test.run_test()
        if result != TEST_INCONCLUSIVE:
          test.mark_chosen(current_exit_idhex, result)
        datahandler.saveTest(test)
        plog("INFO", test.proto+" test via "+current_exit_idhex+" has result "+str(result))
        plog("INFO", test.proto+" attempts: "+str(test.tests_run)+".  Completed: "+str(test.total_nodes - test.scan_nodes)+"/"+str(test.total_nodes)+" ("+str(test.percent_complete())+"%)")

    # Check each test for rewind
    for test in tests.itervalues():
      if test.finished():
        plog("NOTICE", test.proto+" test has finished all nodes.")
        datahandler.saveTest(test)
        test.remove_false_positives()
        if not do_rescan and rescan_at_finish:
          test.toggle_rescan()
          test.rewind()
        elif restart_at_finish:
          test.rewind()
    all_finished = True
    for test in tests.itervalues():
      if not test.finished():
        all_finished = False
    if all_finished:
      plog("NOTICE", "All tests have finished. Exiting\n")
      sys.exit(0)

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
