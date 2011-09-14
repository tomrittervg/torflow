#!/usr/bin/python
#
# Common code to soat

import copy
import difflib
import operator
import os
import pickle
import re
import socket
import struct
import sys
import time
import traceback

if sys.version_info < (2, 5):
    from sets import Set as set

from OpenSSL import crypto

from soat import Tag, SoupStrainer

from soat_config import *

sys.path.append("../../")
from TorCtl.TorUtil import *

# Antlr stuff
sys.path.append("../libs/jsparser/")
import antlr3
from JavaScriptParser import tokenNames as JSTokenNames
from JavaScriptLexer import JavaScriptLexer
from JavaScriptParser import JavaScriptParser


__all__ = [ # Classes
           "LoggingJSParser", "LoggingJSLexer", "TestResult", "SSLTestResult", "SSLDomain", "HttpTestResult",
           "CookieTestResult", "JsTestResult", "HtmlTestResult", "SSHTestResult", "DNSTestResult",
           "DNSRebindTestResult", "SMTPTestResult", "IMAPTestResult", "POPTestResult", "DataHandler",
           "SnakePickler", "SoupDiffer", "HeaderDiffer", "JSDiffer", "JSSoupDiffer",
            # Functions
           "FullyStrainedSoup",
            # Constants
           "COMPARE_EQUAL", "COMPARE_NOEQUAL", "COMPARE_TRUNCATION",
           "TEST_SUCCESS", "TEST_INCONCLUSIVE", "TEST_FAILURE",
           "RESULT_STRINGS", "RESULT_CODES",
           "INCONCLUSIVE_NOLOCALCONTENT", "INCONCLUSIVE_DYNAMICSSL",
           "INCONCLUSIVE_TORBREAKAGE", "INCONCLUSIVE_NOEXIT", "INCONCLUSIVE_REDIRECT",
           "FAILURE_EXITONLY", "FAILURE_DYNAMIC", "FAILURE_COOKIEMISMATCH", "FAILURE_BADHTTPCODE",
           "FAILURE_NOEXITCONTENT", "FAILURE_EXITTRUNCATION", "FAILURE_SOCKSERROR",
           "FAILURE_HOSTUNREACH", "FAILURE_NETUNREACH", "FAILURE_EXITPOLICY", "FAILURE_CONNREFUSED",
           "FAILURE_CONNERROR", "FAILURE_URLERROR", "FAILURE_REDIRECT", "FAILURE_CRYPTOERROR",
           "FAILURE_TIMEOUT", "FAILURE_SLOWXFER", "FAILURE_HEADERCHANGE", "FAILURE_MISCEXCEPTION",
           "FALSEPOSITIVE_HTTPERRORS", "FALSEPOSITIVE_DYNAMIC", "FALSEPOSITIVE_DYNAMIC_TOR",
           "FALSEPOSITIVE_DEADSITE",
           "E_SOCKS", "E_POLICY", "E_NETUNREACH", "E_HOSTUNREACH", "E_REFUSED",
           "E_TIMEOUT", "E_SLOWXFER", "E_NOCONTENT", "E_CRYPTO", "E_URL", "E_MISC", "SOCKS_ERRS",
           # Exception classes
           "SlowXferException", "RedirectException", "NoURLsFound",
          ]


class LoggingJSParser(JavaScriptParser):
  def __init__(self, tokens):
    JavaScriptParser.__init__(self, tokens)
    self.parse_errors__ = []
  def displayRecognitionError(self, tokens, e):
    self.parse_errors__.append(e)
    JavaScriptParser.displayRecognitionError(self, tokens, e)
class LoggingJSLexer(JavaScriptLexer):
  def __init__(self, tokens):
    JavaScriptLexer.__init__(self, tokens)
    self.lex_errors__ = []
  def displayRecognitionError(self, tokens, e):
    self.lex_errors__.append(e)
    JavaScriptLexer.displayRecognitionError(self, tokens, e)

# constants

# Compare results
COMPARE_EQUAL = 0
COMPARE_NOEQUAL = 1
COMPARE_TRUNCATION = 2

# Test results
TEST_SUCCESS = 0
TEST_INCONCLUSIVE = 1
TEST_FAILURE = 2

# Sorry, we sort of rely on the ordinal nature of the above constants
RESULT_STRINGS = {TEST_SUCCESS:"Success", TEST_INCONCLUSIVE:"Inconclusive", TEST_FAILURE:"Failure"}
RESULT_CODES=dict([v,k] for k,v in RESULT_STRINGS.iteritems())

# Inconclusive reasons
INCONCLUSIVE_NOLOCALCONTENT = "InconclusiveNoLocalContent"
INCONCLUSIVE_DYNAMICSSL = "InconclusiveDynamicSSL"
INCONCLUSIVE_TORBREAKAGE = "InconclusiveTorBreakage"
INCONCLUSIVE_NOEXIT = "InconclusiveNoExit"
INCONCLUSIVE_REDIRECT = "InconclusiveRedirect"

# Failed reasons
FAILURE_EXITONLY = "FailureExitOnly"
FAILURE_DYNAMIC = "FailureDynamic" 
FAILURE_COOKIEMISMATCH = "FailureCookieMismatch"
FAILURE_BADHTTPCODE = "FailureBadHTTPCode"
FAILURE_NOEXITCONTENT = "FailureNoExitContent"
FAILURE_EXITTRUNCATION = "FailureExitTruncation"
FAILURE_SOCKSERROR = "FailureSocksError"
FAILURE_HOSTUNREACH = "FailureHostUnreach" # aka DNS issue
FAILURE_NETUNREACH = "FailureNetUnreach"
FAILURE_EXITPOLICY = "FailureExitPolicy"
FAILURE_CONNREFUSED = "FailureConnRefused"
FAILURE_CONNERROR = "FailureConnError"
FAILURE_URLERROR = "FailureURLError"
FAILURE_REDIRECT = "FailureRedirect"
FAILURE_CRYPTOERROR = "FailureCryptoError"
FAILURE_TIMEOUT = "FailureTimeout"
FAILURE_SLOWXFER = "FailureSlowXfer"
FAILURE_HEADERCHANGE = "FailureHeaderChange"
FAILURE_MISCEXCEPTION = "FailureMiscException"

# False positive reasons
FALSEPOSITIVE_HTTPERRORS = "FalsePositiveHTTPErrors"
FALSEPOSITIVE_DYNAMIC = "FalsePositiveDynamic"
FALSEPOSITIVE_DYNAMIC_TOR = "FalsePositiveDynamicTor"
FALSEPOSITIVE_DEADSITE = "FalsePositiveDeadSite"

# Error Codes (Negative floats so as to distinguish from positive int HTTP resp. codes)
E_SOCKS = -1.0
E_POLICY = -2.0
E_NETUNREACH = -3.0
E_HOSTUNREACH = -4.0
E_REFUSED = -5.0
E_TIMEOUT = -6.0
E_SOCKSIPY1 = -7.0 #
E_SOCKSIPY2 = -8.0 # Reserved for SocksiPy
E_SOCKSIPY3 = -9.0 #
E_SLOWXFER = -10.0
E_NOCONTENT = -13.0
E_CRYPTO = -14.0
E_URL = -15.0
E_MISC = -99.0

SOCKS_ERRS = (E_SOCKS, E_POLICY, E_NETUNREACH, E_HOSTUNREACH, E_REFUSED, E_TIMEOUT, E_SOCKSIPY1, E_SOCKSIPY2, E_SOCKSIPY3)
# classes to use with pickle to dump test results into files

class TestResult(object):
  ''' Parent class for all test result classes '''
  def __init__(self, exit_obj, site, status, reason=None):
    if exit_obj:
      self.exit_node = exit_obj.idhex
      self.exit_name = exit_obj.nickname
      self.exit_ip = exit_obj.ip
      self.contact = exit_obj.contact
    else:
      self.exit_node = "[No Exit Used]"
      self.exit_name = ""
      self.exit_ip = 0
      self.contact = "[No Exit Used]"
    self.exit_obj = exit_obj
    self.site = site
    self.timestamp = time.time()
    self.finish_timestamp = None
    self.status = status
    self.reason = reason
    self.extra_info = None
    self.false_positive=False
    self.confirmed=False
    self.false_positive_reason="None"
    self.verbose=0
    self.from_rescan = False
    self.filename=None
    self.exit_result_rate=(0,0) # (Number of times self.exit_node has returned self.reason, total number of results for self.exit_node)
    self.site_result_rate=(0,0) # (Number of exits which have self.reason for self.site, total number of exits that have tested self.site)
    self._pickle_revision = 8

  def depickle_upgrade(self):
    if not "_pickle_revision" in self.__dict__: # upgrade to v0
      self._pickle_revision = 0
    if self._pickle_revision < 1:
      self._pickle_revision = 1
    if self._pickle_revision < 2:
      self._pickle_revision = 2
      self.exit_name = "NameNotStored!"
    if self._pickle_revision < 3:
      self._pickle_revision = 3
      self.exit_ip = "\x00\x00\x00\x00"
      self.exit_obj = None
    if self._pickle_revision < 4:
      self._pickle_revision = 4
      self.contact = None
    if self._pickle_revision < 5:
      self._pickle_revision = 5
      if type(self.exit_ip) == str or not self.exit_ip: self.exit_ip = 0
    if self._pickle_revision < 6:
      self._pickle_revision = 6
      self.confirmed=False
    if self._pickle_revision < 7:
      self._pickle_revision = 7
      self.exit_result_rate = (0,0)
      self.site_result_rate = (0,0)
    if self._pickle_revision < 8:
      self._pickle_revision = 8
      self.finish_timestamp = self.timestamp

  def _rebase(self, filename, new_data_root):
    if not filename: return filename
    filename = os.path.normpath(filename)
    split_file = filename.split("/")
    return os.path.normpath(os.path.join(new_data_root, *split_file[1:]))

  def rebase(self, new_data_root):
    self.filename = self._rebase(self.filename, new_data_root)
 
  def mark_false_positive(self, reason):
    self.false_positive=True
    self.false_positive_reason=reason

  def move_file(self, file, to_dir):
    if not file: return None
    try:
      basename = os.path.basename(file)
      new_file = to_dir+basename
      if not os.path.exists(file) and os.path.exists(new_file):
        return new_file # Already moved by another test (ex: content file)
      os.rename(file, new_file)
      return new_file
    except Exception, e:
      traceback.print_exc()
      plog("WARN", "Error moving "+file+" to "+to_dir)
      return file

  def __str__(self):
    ret = self.__class__.__name__+" for "+self.site+"\n"
    ret += " Time: "+time.ctime(self.timestamp)+"\n"
    if self.finish_timestamp:
      ret += " Test Completed: "+time.ctime(self.finish_timestamp)+"\n"
    ret += " Exit: "+socket.inet_ntoa(struct.pack(">I",self.exit_ip))+" "+self.exit_node+" ("+self.exit_name+")\n"
    ret += " Contact: "+str(self.contact)+"\n"  
    ret += " "+str(RESULT_STRINGS[self.status])
    if self.reason:
      ret += " Reason: "+self.reason
      if self.exit_result_rate != (0,0):
        ret += "\n %s rate for this exit: %d/%d results" % (self.reason, self.exit_result_rate[0], self.exit_result_rate[1])
      if self.site_result_rate != (0,0):
        ret += "\n %s rate for this site: %d/%d exits" % (self.reason, self.site_result_rate[0], self.site_result_rate[1])
    if self.extra_info:
      ret += "\n Extra info: "+self.extra_info 
    if self.false_positive:
      ret += "\n Removed as False Positive: "+self.false_positive_reason
    if self.from_rescan:
      ret += "\n From rescan: "+str(self.from_rescan)
    if self.confirmed:
      ret += "\n Confirmed. "
    ret += "\n"
    return ret

class SSLTestResult(TestResult):
  ''' Represents the result of an openssl test '''
  def __init__(self, exit_obj, ssl_site, ssl_file, status, 
               reason=None, resolved_ip=0, exit_cert_pem=None):
    super(SSLTestResult, self).__init__(exit_obj, ssl_site, status, reason)
    self.ssl_file = ssl_file
    self.exit_cert = exit_cert_pem # Meh, not that much space
    self.resolved_ip = resolved_ip
    self.proto = "ssl"

  def depickle_upgrade(self):
    TestResult.depickle_upgrade(self)
    if self.exit_ip is None:
      self.exit_ip = 0

  def rebase(self, new_data_root):
    self.ssl_file = self._rebase(self.ssl_file, new_data_root)

  def mark_false_positive(self, reason):
    TestResult.mark_false_positive(self, reason)
    self.ssl_file=self.move_file(self.ssl_file, ssl_falsepositive_dir)

  def _dump_cert(self, cert):
    ret = ""
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    ret += "Issuer: "+str(x509.get_issuer())+"\n"
    ret += "Subject: "+str(x509.get_subject())+"\n"
    return ret

  def __str__(self):
    ret = TestResult.__str__(self)
    ssl_domain = SnakePickler.load(self.ssl_file)
    ret += " Rotates: "+str(ssl_domain.cert_rotates)
    ret += " Changed: "+str(ssl_domain.cert_changed)+"\n" 
    if self.verbose:
      if self.exit_cert:
        for cert in ssl_domain.cert_map.iterkeys():
          ret += "\nCert for "+ssl_domain.cert_map[cert]+":\n"
          if self.verbose > 1: ret += cert
          ret += self._dump_cert(cert)
        if self.resolved_ip: 
          ret += "\nExit node's cert for "+self.resolved_ip+":\n"
        else:
          ret += "\nExit node's cert:\n"
        if self.verbose > 1: ret += self.exit_cert
        ret += self._dump_cert(self.exit_cert)
    return ret 

class SSLDomain:
  def __init__(self, domain):
    self.domain = domain
    self.cert_map = {}
    self.ip_map = {}
    self.cert_rotates = False
    self.cert_changed = False

  def depickle_upgrade(self):
    pass

  def add_cert(self, ip, cert_string):
    if ip in self.ip_map and self.ip_map[ip] != cert_string:
      plog("NOTICE", self.domain+" has changed certs.")
      self.cert_changed = True
    if len(self.cert_map) and cert_string not in self.cert_map:
      plog("NOTICE", self.domain+" is rotating certs.")
      self.cert_rotates = True
    self.cert_map[cert_string] = ip
    self.ip_map[ip] = cert_string
    
  def seen_cert(self, cert_string):
    return cert_string in self.cert_map

  def seen_ip(self, ip):
    return ip in self.ip_map

  def num_certs(self):
    return len(self.cert_map)

class HttpTestResult(TestResult):
  ''' Represents the result of a http test '''
  def __init__(self, exit_obj, website, status, reason=None, 
               sha1sum=None, exit_sha1sum=None, content=None, 
               content_exit=None, content_old=None, sha1sum_old=None):
    super(HttpTestResult, self).__init__(exit_obj, website, status, reason)
    self.proto = "http"
    self.sha1sum = sha1sum
    self.sha1sum_old = sha1sum_old
    self.exit_sha1sum = exit_sha1sum
    self.content = content
    self.content_exit = content_exit
    self.content_old = content_old

  def rebase(self, new_data_root):
    self.content = self._rebase(self.content, new_data_root)
    self.content_exit = self._rebase(self.content_exit, new_data_root)
    self.content_old = self._rebase(self.content_old, new_data_root)

  def mark_false_positive(self, reason):
    TestResult.mark_false_positive(self, reason)
    self.content=self.move_file(self.content, http_falsepositive_dir)
    self.content_old=self.move_file(self.content_old, http_falsepositive_dir)
    self.content_exit=self.move_file(self.content_exit,http_falsepositive_dir)

  def remove_files(self):
    try: os.unlink(self.content)
    except: pass
    try: os.unlink(self.content_old)
    except: pass
    try: os.unlink(self.content_exit)
    except: pass

  def __str__(self):
    ret = TestResult.__str__(self)
    if self.content:
      ret += " "+self.content+" (SHA1: "+self.sha1sum+")\n"
    if self.content_old:
      ret += " "+self.content_old+" (SHA1: "+self.sha1sum_old+")\n"
    if self.content_exit:
      ret += " "+self.content_exit+" (SHA1: "+self.exit_sha1sum+")\n"
    return ret

class CookieTestResult(TestResult):
  def __init__(self, exit_obj, status, reason, plain_cookies, 
               tor_cookies):
    super(CookieTestResult, self).__init__(exit_obj, "cookies", status)
    self.proto = "http"
    self.reason = reason
    self.tor_cookies = tor_cookies
    self.plain_cookies = plain_cookies

  def __str__(self):
    ret = TestResult.__str__(self)
    ret += " Plain Cookies:"+self.plain_cookies
    ret += " Tor Cookies:"+self.tor_cookies
    return ret

class JsTestResult(TestResult):
  ''' Represents the result of a JS test '''
  def __init__(self, exit_obj, website, status, reason=None, 
               content=None, content_exit=None, content_old=None,
               jsdiffer=None):
    super(JsTestResult, self).__init__(exit_obj, website, status, reason)
    self.proto = "http"
    self.content = content
    self.content_exit = content_exit
    self.content_old = content_old
    self.jsdiffer = jsdiffer

  def depickle_upgrade(self):
    if not "_pickle_revision" in self.__dict__ or self._pickle_revision < 1:
      self.jsdiffer = None
    TestResult.depickle_upgrade(self)

  def rebase(self, new_data_root):
    self.content = self._rebase(self.content, new_data_root)
    self.content_exit = self._rebase(self.content_exit, new_data_root)
    self.content_old = self._rebase(self.content_old, new_data_root)
    self.jsdiffer = self._rebase(self.jsdiffer, new_data_root)

  def mark_false_positive(self, reason):
    TestResult.mark_false_positive(self, reason)
    self.content=self.move_file(self.content, http_falsepositive_dir)
    self.content_old=self.move_file(self.content_old, http_falsepositive_dir)
    self.content_exit=self.move_file(self.content_exit,http_falsepositive_dir)
    self.jsdiffer=self.move_file(self.jsdiffer,http_falsepositive_dir)

  def remove_files(self):
    try: os.unlink(self.content)
    except: pass
    try: os.unlink(self.content_old)
    except: pass
    try: os.unlink(self.content_exit)
    except: pass

  def __str__(self):
    ret = TestResult.__str__(self)
    if self.verbose:
      if self.content and self.content_old:
        diff = difflib.unified_diff(open(self.content).read().split("\n"),
                             open(self.content_old).read().split("\n"), 
                             "Non-Tor1", "Non-Tor2",
                             lineterm="")
        for line in diff:
          ret+=line+"\n"
      if self.content and self.content_exit:
        diff = difflib.unified_diff(open(self.content).read().split("\n"),
                             open(self.content_exit).read().split("\n"), 
                              "Non-Tor", "Exit",
                              lineterm="")
        for line in diff:
          ret+=line+"\n"
    else:
      if self.content:
        ret += " "+self.content+"\n"
      if self.content_old:
        ret += " "+self.content_old+"\n"
      if self.content_exit:
        ret += " "+self.content_exit+"\n"
    return ret

class HtmlTestResult(TestResult):
  ''' Represents the result of a http test '''
  def __init__(self, exit_obj, website, status, reason=None, 
               content=None, content_exit=None, content_old=None, 
               soupdiffer=None, jsdiffer=None):
    super(HtmlTestResult, self).__init__(exit_obj, website, status, reason)
    self.proto = "http"
    self.content = content
    self.content_exit = content_exit
    self.content_old = content_old
    self.soupdiffer = soupdiffer
    self.jsdiffer = jsdiffer

  def depickle_upgrade(self):
    if not "_pickle_revision" in self.__dict__ or self._pickle_revision < 1:
      self.soupdiffer = None
      self.jsdiffer = None
    TestResult.depickle_upgrade(self)

  def rebase(self, new_data_root):
    self.content = self._rebase(self.content, new_data_root)
    self.content_exit = self._rebase(self.content_exit, new_data_root)
    self.content_old = self._rebase(self.content_old, new_data_root)
    self.soupdiffer = self._rebase(self.soupdiffer, new_data_root)
    self.jsdiffer = self._rebase(self.jsdiffer, new_data_root)

  def mark_false_positive(self, reason):
    TestResult.mark_false_positive(self, reason)
    self.content=self.move_file(self.content,http_falsepositive_dir)
    self.content_old=self.move_file(self.content_old, http_falsepositive_dir)
    self.content_exit=self.move_file(self.content_exit,http_falsepositive_dir)
    self.soupdiffer=self.move_file(self.soupdiffer,http_falsepositive_dir)
    self.jsdiffer=self.move_file(self.jsdiffer,http_falsepositive_dir)

  def remove_files(self):
    try: os.unlink(self.content)
    except: pass
    try: os.unlink(self.content_old)
    except: pass
    try: os.unlink(self.content_exit)
    except: pass

  def __str__(self):
    ret = TestResult.__str__(self)
    if self.verbose:
      soup = old_soup = tor_soup = None
      if self.content:
        content = open(self.content).read().decode('ascii', 'ignore')
        soup = FullyStrainedSoup(content)

      if self.content_old:
        content_old = open(self.content_old).read().decode('ascii', 'ignore')
        old_soup = FullyStrainedSoup(content_old)

      if self.content_exit:
        content_exit = open(self.content_exit).read().decode('ascii', 'ignore')
        tor_soup = FullyStrainedSoup(content_exit)

      if self.verbose > 1:
        ret += " Content: "+str(self.content)+"\n"
        ret += " Content old: "+str(self.content_old)+"\n"
        ret += " Exit: "+str(self.content_exit)+"\n"

        if self.content and self.content_old:
          tags = map(str, soup.findAll())
          old_tags = map(str, old_soup.findAll())
          diff = difflib.unified_diff(old_tags, tags, "Non-Tor1", "Non-Tor2",
                                      lineterm="")
          for line in diff:
            ret+=line+"\n"

        if self.content and self.content_exit:
          tags = map(str, soup.findAll())
          tor_tags = map(str, tor_soup.findAll())
          diff = difflib.unified_diff(tags, tor_tags, "Non-Tor", "Exit",
                                      lineterm="")
          for line in diff:
            ret+=line+"\n"

      if soup and tor_soup and old_soup:
        if self.soupdiffer and os.path.exists(self.soupdiffer):
          soupdiff = SnakePickler.load(self.soupdiffer)
        else:
          soupdiff = SoupDiffer(old_soup, soup)

        more_tags = soupdiff.show_changed_tags(tor_soup)     
        more_attrs = soupdiff.show_changed_attrs(tor_soup)
        more_content = soupdiff.show_changed_content(tor_soup)

        if more_tags:
          ret += "\nTor changed tags:\n"
          ret += more_tags
        if more_attrs:
          ret += "\nTor changed attrs:\n"
          ret += more_attrs
        if not soupdiff.content_changed and more_content:
          ret += "\nChanged Content:\n"
          ret += "\n".join(more_content)+"\n"
        if (soupdiff.content_changed or not more_content) and not more_tags and not more_attrs:
          ret += "\nSoupDiffer claims false positive.\n"
          jsdiff = JSSoupDiffer(old_soup)
          jsdiff.prune_differences(soup)
          jsdifferences = jsdiff.show_differences(tor_soup)
          if not jsdifferences: jsdifferences = "None."
          ret += "Javascript Differences: "+jsdifferences+"\n"
    else:
      if self.content:
        ret += " "+self.content+"\n"
      if self.content_old:
        ret += " "+self.content_old+"\n"
      if self.content_exit:
        ret += " "+self.content_exit+"\n"
    return ret

class SSHTestResult(TestResult):
  ''' Represents the result of an ssh test '''
  def __init__(self, exit_obj, ssh_site, status):
    super(SSHTestResult, self).__init__(exit_obj, ssh_site, status)
    self.proto = "ssh"

class DNSTestResult(TestResult):
  ''' Represents the result of a dns test '''
  def __init__(self, exit_obj, dns_site, status):
    super(DNSTestResult, self).__init__(exit_obj, dns_site, status)
    self.proto = "dns"

class DNSRebindTestResult(TestResult):
  ''' Represents the result of a dns rebind test '''
  def __init__(self, exit_obj, dns_rebind_site, status):
    super(DNSRebindTestResult, self).__init__(exit_obj, dns_rebind_site, status)
    self.proto = "dns"

class SMTPTestResult(TestResult):
  ''' Represents the result of an smtp test '''
  def __init__(self, exit_obj, smtp_site, status):
    super(SMTPTestResult, self).__init__(exit_obj, smtp_site, status)
    self.proto = "smtp"

class IMAPTestResult(TestResult):
  ''' Represents the result of an imap test '''
  def __init__(self, exit_obj, imap_site, status):
    super(IMAPTestResult, self).__init__(exit_obj, imap_site, status)
    self.proto = "imap"

class POPTestResult(TestResult):
  ''' Represents the result of a pop test '''
  def __init__(self, exit_obj, pop_site, status):
    super(POPTestResult, self).__init__(exit_obj, pop_site, status)
    self.proto = "pop"

class DataHandler:
  def __init__(self, my_data_dir=soat_dir):
    self.data_dir = my_data_dir

  ''' Class for saving and managing test result data '''
  def filterResults(self, results, protocols=[], show_good=False, 
      show_bad=False, show_inconclusive=False):
    ''' filter results based on protocol and success level ''' 

    protocol_filters = []
    status_filters = []

    for protocol in protocols:
      protocol_filters.append(lambda x, p=protocol: x.__class__.__name__.lower()[:-10].endswith(p))
    if show_good:
      status_filters.append(lambda x: x.status == TEST_SUCCESS)
    if show_bad:
      status_filters.append(lambda x: x.status == TEST_FAILURE)
    if show_inconclusive:
      status_filters.append(lambda x: x.status == TEST_INCONCLUSIVE)

    if len(protocol_filters) == 0 or len(status_filters) == 0:
      return []
     
    protocol_filter = lambda x: reduce(operator.__or__, [f(x) for f in protocol_filters])
    status_filter = lambda x: reduce(operator.__or__, [f(x) for f in status_filters])

    return [x for x in results if (protocol_filter(x) and status_filter(x))]
    
  def filterByNode(self, results, id):
    ''' filter by node'''
    return filter(lambda x: x.exit_node == id, results)

  def getAll(self):
    ''' get all available results'''
    return self.__getResults(self.data_dir)

  def getSsh(self):
    ''' get results of ssh tests '''
    return self.__getResults(self.data_dir + 'ssh/')
    
  def getHttp(self):
    ''' get results of http tests '''
    return self.__getResults(self.data_dir + 'http/')

  def getSsl(self):
    ''' get results of ssl tests '''
    return self.__getResults(self.data_dir + 'ssl/')

  def getSmtp(self):
    ''' get results of smtp tests '''
    return self.__getResults(self.data_dir + 'smtp/')

  def getPop(self):
    ''' get results of pop tests '''
    return self.__getResults(self.data_dir + 'pop/')

  def getImap(self):
    ''' get results of imap tests '''
    return self.__getResults(self.data_dir + 'imap/')

  def getDns(self):
    ''' get results of basic dns tests '''
    return self.__getResults(self.data_dir + 'dns')

  def getDnsRebind(self):
    ''' get results of dns rebind tests '''
    return self.__getResults(self.data_dir + 'dnsbrebind/')

  def __getResults(self, rdir):
    ''' 
    recursively traverse the directory tree starting with dir
    gather test results from files ending with .result
    '''
    results = []

    for root, dirs, files in os.walk(rdir):
      for f in files:
        if f.endswith('.result'):
          result = SnakePickler.load(os.path.join(root, f))
          result.rebase(self.data_dir)
          results.append(result)
    return results

  def getResult(self, file):
    return SnakePickler.load(file)

  def uniqueFilename(afile):
    (prefix,suffix)=os.path.splitext(afile)
    i=0
    while os.path.exists(prefix+"."+str(i)+suffix):
      i+=1
    return prefix+"."+str(i)+suffix
  uniqueFilename = Callable(uniqueFilename)
  
  def safeFilename(unsafe_file):
    ''' 
    remove characters illegal in some systems 
    and trim the string to a reasonable length
    '''
    unsafe_file = unsafe_file.decode('ascii', 'ignore')
    safe_file = re.sub(unsafe_filechars, "_", unsafe_file)
    return str(safe_file[:200])
  safeFilename = Callable(safeFilename)

  def __resultFilename(self, result):
    address = ''
    if result.__class__.__name__ in ('HtmlTestResult', 'HttpTestResult'):
      address = DataHandler.safeFilename(result.site.replace('http://',''))
    elif result.__class__.__name__ == 'SSLTestResult':
      address = DataHandler.safeFilename(result.site.replace('https://',''))
    elif 'TestResult' in result.__class__.__name__:
      address = DataHandler.safeFilename(result.site)
    else:
      raise Exception, 'This doesn\'t seems to be a result instance.'

    rdir = self.data_dir+result.proto.lower()+'/'
    if result.confirmed:
      rdir += 'confirmed/'
    elif result.false_positive:
      rdir += 'falsepositive/'
    elif result.from_rescan:
      rdir += 'rescan/'
    elif result.status == TEST_SUCCESS:
      rdir += 'successful/'
    elif result.status == TEST_INCONCLUSIVE:
      rdir += 'inconclusive/'
    elif result.status == TEST_FAILURE:
      rdir += 'failed/'

    return DataHandler.uniqueFilename(str((rdir+address+'.'+result.exit_node[1:]+".result").decode('ascii', 'ignore')))

  def checkResultDir(self, dir):
    if not dir.startswith(self.data_dir):
      return False
    if not os.path.exists(dir):
      try:
        os.makedirs(dir, 0700)
      except OSError, e:
        plog("WARN", "Unable to create results directory %s. %s" % (dir, e))
        return False
    elif not os.access(dir, os.R_OK|os.W_OK):
      return False
    return True

  def saveResult(self, result):
    ''' generic method for saving test results '''
    if result.filename is None:
      result.filename = self.__resultFilename(result)
    SnakePickler.dump(result, result.filename)

  def __testFilename(self, test, position=-1):
    if hasattr(test, "save_name"):
      name = test.save_name
    else:
      name = test.__class__.__name__
    if position == -1:
      return DataHandler.uniqueFilename(self.data_dir+name+".test")
    else:
      return self.data_dir+name+"."+str(position)+".test"

  def loadTest(self, testname, position=-1):
    filename = self.data_dir+testname
    if position == -1:
      i=0
      while os.path.exists(filename+"."+str(i)+".test"):
        i+=1
      position = i-1
    
    test = SnakePickler.load(filename+"."+str(position)+".test")
    return test

  def saveTest(self, test):
    if not test.filename:
      test.filename = self.__testFilename(test)
    SnakePickler.dump(test, test.filename)

# These three bits are needed to fully recursively strain the parsed soup.
# For some reason, the SoupStrainer does not get applied recursively..
__first_strainer = SoupStrainer(lambda name, attrs: name in tags_to_check or 
   len(set(map(lambda a: a[0], attrs)).intersection(set(attrs_to_check))) > 0)

def __tag_not_worthy(tag):
  if tag.name in tags_to_check:
    return False
  for attr in tag.attrs:
    if attr[0] in attrs_to_check_map:
      return False
  return True

def FullyStrainedSoup(html):
  """ Remove all tags that are of no interest. Also remove content """
  soup = TheChosenSoup(html, __first_strainer)
  to_extract = []
  for tag in soup.findAll():
    to_prune = []
    for attr in tag.attrs:
      if attr[0] in attrs_to_prune:
        to_prune.append(attr)
    for attr in to_prune:
      tag.attrs.remove(attr)
    if __tag_not_worthy(tag):
      to_extract.append(tag)
    if tag.name not in tags_preserve_inner:
      for child in tag.childGenerator():
        if not isinstance(child, Tag) or __tag_not_worthy(child):
          to_extract.append(child)
  for tag in to_extract:
    if isinstance(tag, Tag):
      parent = tag.findParent()
      for child in tag.findChildren():
        parent.append(child)
  for tag in to_extract:
    tag.extract()
  # Also flatten the tag structure
  flattened_tags = soup.findAll()
  for tag in flattened_tags:
    if isinstance(tag, Tag): # Don't extract script/CSS strings.
      tag.extract() 
  for tag in flattened_tags:
    soup.append(tag)
  return soup      

class SnakePickler:
  def dump(obj, filename):
    if not "depickle_upgrade" in dir(obj.__class__):
      plog("WARN", "Pickling instance of "+obj.__class__.__name__+" without upgrade method")
    f = file(filename, "w")
    try:
      pickle.dump(obj, f)
    except KeyboardInterrupt:
      finished = False
      while not finished:
        try:
          f.close()
          f = file(filename, "w")
          pickle.dump(obj, f)
          f.close()
          finished = True
        except KeyboardInterrupt:
          pass
      raise KeyboardInterrupt
    except Exception, e:
      plog("WARN", "Exception during pickle dump: " + str(e))
      try:
        os.unlink(filename)
      except: pass
    f.close()
  dump = Callable(dump)

  def load(filename):
    f = file(filename, "r")
    try:
      obj = pickle.load(f)
    except Exception, e:
      plog("WARN", "Error loading object from "+filename+": "+str(e))
      return None
    if not "depickle_upgrade" in dir(obj.__class__):
      plog("WARN", "De-pickling instance of "+obj.__class__.__name__+" without upgrade method")
    else:
      obj.depickle_upgrade()
    f.close()
    return obj
  load = Callable(load)
     
class SoupDiffer:
  """ Diff two soup tag sets, optionally writing diffs to outfile. """
  def __init__(self, soup_old, soup_new):
    tags_old = self._get_tags(soup_old)
    tags_new = self._get_tags(soup_new)
    self.tag_pool = tags_new | tags_old
    self.changed_tag_map = {}
    self._update_changed_tag_map(tags_old, tags_new)
    self._update_changed_tag_map(tags_new, tags_old)

    attrs_new = self._get_attributes(soup_new)
    attrs_old = self._get_attributes(soup_old)
    self.attr_pool = attrs_new | attrs_old
    self.changed_attr_map = {}
    self._update_changed_attr_map(attrs_new, attrs_old)
    self._update_changed_attr_map(attrs_old, attrs_new)

    cntnt_new = self._get_content(soup_new)
    cntnt_old = self._get_content(soup_old)
    self.content_pool = cntnt_new | cntnt_old
    self.content_changed = bool(cntnt_new ^ cntnt_old) 
    self._pickle_revision = 0    

  def depickle_upgrade(self):
    pass

  def _get_tags(self, soup):
    return set(map(str,
           [tag for tag in soup.findAll() if isinstance(tag, Tag)]))

  def _get_attributes(self, soup):
    attr_soup = [(tag.name, tag.attrs) for tag in soup.findAll()]
    attrs = set([])
    for (tag, attr_list) in attr_soup:
      for at in attr_list:
        attrs.add((tag, at)) 
    return attrs

  def _get_content(self, soup):
    return set(map(str,
      [tag for tag in soup.findAll() if not isinstance(tag, Tag)]))
  
  def _update_changed_tag_map(self, tags_old, tags_new):
    """ Create a map of changed tags to ALL attributes that tag
        has ever had (changed or not) """
    changed_tags = list(tags_new - tags_old)
    for tags in map(TheChosenSoup, changed_tags):
      for t in tags.findAll():
        if t.name not in changed_tags:
          self.changed_tag_map[t.name] = set([])
        for attr in t.attrs:
          self.changed_tag_map[t.name].add(attr[0])

  def _update_changed_attr_map(self, attrs_old, attrs_new):
    """ Transform the list of (tag, attribute) pairings for new/changed
        attributes into a map. This allows us to quickly see
        if any attributes changed for a specific tag. """
    changed_attributes = list(attrs_new - attrs_old)
    for (tag, attr) in changed_attributes:
      if tag not in self.changed_attr_map:
        self.changed_attr_map[tag] = set([])
      self.changed_attr_map[tag].add(attr[0])

  def _update_changed_content(self, content_old, content_new):
    # FIXME: This could be tracked by parent tag+attr
    if not self.content_changed:
      self.content_changed = bool(content_old ^ content_new)

  def prune_differences(self, soup):
    tags = self._get_tags(soup)
    attrs = self._get_attributes(soup)
    cntnt = self._get_content(soup)

    self._update_changed_tag_map(self.tag_pool, tags)
    self._update_changed_attr_map(self.attr_pool, attrs)
    self._update_changed_content(self.content_pool, cntnt)
    self.tag_pool.update(tags)
    self.attr_pool.update(attrs)
    self.content_pool.update(cntnt)

  def show_changed_tags(self, soup):
    soup_tags = self._get_tags(soup)
    new_tags = soup_tags - self.tag_pool
    ret = ""
    for tags in map(TheChosenSoup, new_tags):
      for t in tags.findAll():
        if t.name not in self.changed_tag_map:
          ret += " New Tag: "+str(t)+"\n"
        else:
          for attr in t.attrs:
            if attr[0] not in self.changed_tag_map[t.name] \
                 and attr[0] in attrs_to_check_map:
              ret += " New Attr "+attr[0]+": "+str(t)+"\n"
    return ret

  def show_changed_attrs(self, soup):
    soup_attrs = self._get_attributes(soup)
    new_attrs = soup_attrs - self.attr_pool
    ret = ""
    for (tag, attr) in new_attrs:
      if tag in self.changed_attr_map:
        if attr[0] not in self.changed_attr_map[tag] \
            and attr[0] in attrs_to_check_map:
          ret += " New Attr "+attr[0]+": "+tag+" "+attr[0]+'="'+attr[1]+'"\n'
      else:
        ret += " New Tag: "+tag+" "+attr[0]+'="'+attr[1]+'"\n'
    return ret

  def show_changed_content(self, soup):
    """ Return a list of tag contents changed in soup_new """
    content = self._get_content(soup)
    ret = list(content - self.content_pool)
    ret.sort()
    return ret

class HeaderDiffer:
  def __init__(self, orig_headers):
    self.header_pool = set(orig_headers or [])
    self.changed_headers = set([])
    self._pickle_revision = 0
 
  def filter_headers(headers):
    ret = []
    for h in headers:
      matched = False
      for i in ignore_http_headers:
        if re.match(i, h[0]):
          matched = True
      if not matched: ret.append(h)
    return set(ret)
  filter_headers = Callable(filter_headers)
 
  def depickle_upgrade(self):
    pass

  def prune_differences(self, new_headers):
    new_headers = set(new_headers or [])
    changed = new_headers - self.header_pool
    for i in changed:
      self.changed_headers.add(i[0])
    self.header_pool.update(new_headers)

  def show_differences(self, new_headers):
    ret = ""
    changed = set(new_headers or []) - self.header_pool
    for i in changed:
      if i[0] not in self.changed_headers:
        ret += " "+i[0]+": "+i[1]+"\n"
    if ret:
      return "New HTTP Headers:\n"+ret
    else: 
      return ret

class JSDiffer:
  def __init__(self, js_string):
    self._pickle_revision = 0    
    self.ast_cnts = self._count_ast_elements(js_string)

  def depickle_upgrade(self):
    pass

  def _ast_recursive_worker(ast, ast_cnts):
    node = JSTokenNames[ast.getType()]
    if not node in ast_cnts:
      ast_cnts[node] = 1
    else: ast_cnts[node] += 1

    for child in ast.getChildren():
      JSDiffer._ast_recursive_worker(child, ast_cnts)
  _ast_recursive_worker = Callable(_ast_recursive_worker)

  def _antlr_parse(self, js_string):
    char_stream = antlr3.ANTLRStringStream(js_string)
    lexer = LoggingJSLexer(char_stream)
    tokens = antlr3.CommonTokenStream(lexer)
    parser = LoggingJSParser(tokens)
    program = parser.program()
    program.tree.parse_errors = parser.parse_errors__
    program.tree.lex_errors = lexer.lex_errors__
    return program.tree
                            
  def _count_ast_elements(self, js_string, name="global"):
    ast_cnts = {}
    try:
      js_string = js_string.replace("\n\r","\n").replace("\r\n","\n").replace("\r","\n")+";"
      
      ast = self._antlr_parse(js_string)
      JSDiffer._ast_recursive_worker(ast, ast_cnts)
      for e in ast.lex_errors+ast.parse_errors:
        name+=":"+e.__class__.__name__
        if "line" in e.__dict__: 
          name+=":"+str(e.line)
        if "token" in e.__dict__ and e.token \
            and "type" in e.token.__dict__: 
          name+=":"+JSTokenNames[e.token.type]
        # XXX: Any other things we want to add?
        plog("INFO", "Parse error "+name+" on "+js_string)
        if not "ParseError:"+name in ast_cnts:
          ast_cnts["ParseError:"+name] = 1
        else: ast_cnts["ParseError:"+name] += 1
    except UnicodeDecodeError, e:
      name+=":"+e.__class__.__name__
      plog("INFO", "Unicode error "+name+" on "+js_string)
      if not "ParseError:"+name in ast_cnts:
        ast_cnts["ParseError:"+name] = 1
      else: ast_cnts["ParseError:"+name] +=1
    return ast_cnts

  def _difference_pruner(self, other_cnts):
    for node in self.ast_cnts.iterkeys():
      if node not in other_cnts:
        self.ast_cnts[node] = 0
      elif self.ast_cnts[node] != other_cnts[node]:
        self.ast_cnts[node] = 0
    for node in other_cnts.iterkeys():
      if node not in self.ast_cnts:
        self.ast_cnts[node] = 0

  def _difference_checker(self, other_cnts):
    for node in self.ast_cnts.iterkeys():
      if not self.ast_cnts[node]: continue # pruned difference
      if node not in other_cnts:
        return True
      elif self.ast_cnts[node] != other_cnts[node]:
        return True
    for node in other_cnts.iterkeys():
      if node not in self.ast_cnts:
        return True
    return False

  def _difference_printer(self, other_cnts):
    ret = ""
    missing = []
    miscount = []
    new = []
    for node in self.ast_cnts.iterkeys():
      if not self.ast_cnts[node]: continue # pruned difference
      if node not in other_cnts:
        missing.append(str(node))
      elif self.ast_cnts[node] != other_cnts[node]:
        miscount.append(str(node))
    for node in other_cnts.iterkeys():
      if node not in self.ast_cnts:
        new.append(str(node))
    if missing:
      ret += "\nMissing: "
      for node in missing: ret += node+" "
    if new:
      ret += "\nNew: "
      for node in new: ret += node+" "
    if miscount:
      ret += "\nMiscount: "
      for node in miscount: ret += node+" "
    return ret

  def prune_differences(self, other_string):
    other_cnts = self._count_ast_elements(other_string)
    self._difference_pruner(other_cnts)

  def contains_differences(self, other_string):
    other_cnts = self._count_ast_elements(other_string)
    return self._difference_checker(other_cnts) 

  def show_differences(self, other_string):
    other_cnts = self._count_ast_elements(other_string)
    return self._difference_printer(other_cnts) 


class JSSoupDiffer(JSDiffer):
  def _add_cnts(tag_cnts, ast_cnts):
    ret_cnts = {}
    for n in tag_cnts.iterkeys():
      if n in ast_cnts:
        ret_cnts[n] = tag_cnts[n]+ast_cnts[n]
      else:
        ret_cnts[n] = tag_cnts[n]
    for n in ast_cnts.iterkeys():
      if n not in tag_cnts:
        ret_cnts[n] = ast_cnts[n]
    return ret_cnts
  _add_cnts = Callable(_add_cnts)

  def _count_ast_elements(self, soup, name="Soup"):
    ast_cnts = {}
    for tag in soup.findAll():
      if tag.name == 'script':
        for child in tag.childGenerator():
          if isinstance(child, Tag):
            plog("ERROR", "Script tag with subtag!")
          else:
            script = str(child).replace("<!--", "").replace("-->", "").replace("<![CDATA[", "").replace("]]>", "")
            tag_cnts = JSDiffer._count_ast_elements(self, script, tag.name)
            ast_cnts = JSSoupDiffer._add_cnts(tag_cnts, ast_cnts)
      for attr in tag.attrs:
        # hrmm.. %-encoding too? Firefox negs on it..
        parse = ""
        if attr[1].replace(" ","")[:11] == "javascript:":
          split_at = attr[1].find(":")+1
          parse = str(attr[1][split_at:])
        elif attr[0] in attrs_with_raw_script_map:
          parse = str(attr[1])
        if not parse: continue
        tag_cnts = JSDiffer._count_ast_elements(self,parse,tag.name+":"+attr[0])
        ast_cnts = JSSoupDiffer._add_cnts(tag_cnts, ast_cnts)
    return ast_cnts


class SlowXferException(Exception):
  pass

class RedirectException(Exception):
  def __init__(self, code, orig, new):
    self.code = code
    self.orig_url = orig
    self.new_url = new

  def __str__(self):
    return "HTTP %d Redirect: %s --> %s" % (self.code, self.orig_url, self.new_url)

class NoURLsFound(Exception):
  pass
