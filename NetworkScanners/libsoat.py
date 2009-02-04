#!/usr/bin/python
#
# Common code to soat

import dircache
import operator
import os
import pickle
import sys
import time
import traceback
sys.path.append("./libs")
from BeautifulSoup.BeautifulSoup import BeautifulSoup, Tag


import sets
from sets import Set

from soat_config import *
sys.path.append("../")
from TorCtl.TorUtil import *

try:
  sys.path.append("./libs/pypy-svn/")
  import pypy.rlib.parsing.parsing
  import pypy.lang.js.jsparser
  HAVE_PYPY = True
except ImportError:
  HAVE_PYPY = False

# constants

TEST_SUCCESS = 0
TEST_INCONCLUSIVE = 1
TEST_FAILURE = 2

# Inconclusive reasons
INCONCLUSIVE_NOEXITCONTENT = "InconclusiveNoExitContent"
INCONCLUSIVE_NOLOCALCONTENT = "InconclusiveNoLocalContent"
INCONCLUSIVE_BADHTTPCODE = "InconclusiveBadHTTPCode"

# Failed reasons
FAILURE_EXITONLY = "FailureExitOnly"
FAILURE_DYNAMICTAGS = "FailureDynamicTags" 
FAILURE_DYNAMICJS = "FailureDynamicJS" 
FAILURE_DYNAMICBINARY = "FailureDynamicBinary" 
FAILURE_COOKIEMISMATCH = "FailureCookieMismatch"

# classes to use with pickle to dump test results into files

class TestResult(object):
  ''' Parent class for all test result classes '''
  def __init__(self, exit_node, site, status):
    self.exit_node = exit_node
    self.site = site
    self.timestamp = time.time()
    self.status = status
    self.false_positive=False
  
  def mark_false_positive(self):
    pass

  def move_file(self, file, to_dir):
    try:
      basename = os.path.basename(file)
      new_file = to_dir+basename
      os.rename(file, new_file)
      return new_file
    except:
      traceback.print_exc()
      plog("WARN", "Error moving "+file+" to "+dir)
      return file

class SSLTestResult(TestResult):
  ''' Represents the result of an openssl test '''
  def __init__(self, exit_node, ssl_site, cert_file, status):
    super(SSLTestResult, self).__init__(exit_node, ssl_site, status)
    self.cert = cert_file
    self.proto = "ssl"

class HttpTestResult(TestResult):
  ''' Represents the result of a http test '''
  def __init__(self, exit_node, website, status, reason=None, 
               sha1sum=None, exit_sha1sum=None, content=None, 
               content_exit=None, content_old=None, sha1sum_old=None):
    super(HttpTestResult, self).__init__(exit_node, website, status)
    self.proto = "http"
    self.reason = reason
    self.sha1sum = sha1sum
    self.sha1sum_old = sha1sum_old
    self.exit_sha1sum = exit_sha1sum
    self.content = content
    self.content_exit = content_exit
    self.content_old = content_old

  def mark_false_positive(self):
    self.false_positive=True
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

class CookieTestResult(TestResult):
  def __init__(self, exit_node, status, reason, plain_cookies, 
               tor_cookies):
    super(CookieTestResult, self).__init__(exit_node, "cookies", status)
    self.proto = "http"
    self.reason = reason
    self.tor_cookies = tor_cookies
    self.plain_cookies = plain_cookies

class JsTestResult(TestResult):
  ''' Represents the result of a JS test '''
  def __init__(self, exit_node, website, status, reason=None, 
               content=None, content_exit=None, content_old=None):
    super(JsTestResult, self).__init__(exit_node, website, status)
    self.proto = "http"
    self.reason = reason
    self.content = content
    self.content_exit = content_exit
    self.content_old = content_old

  def mark_false_positive(self):
    self.false_positive=True
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

class HtmlTestResult(TestResult):
  ''' Represents the result of a http test '''
  def __init__(self, exit_node, website, status, reason=None, 
               tags=None, exit_tags=None, content=None, 
               content_exit=None, content_old=None, tags_old=None):
    super(HtmlTestResult, self).__init__(exit_node, website, status)
    self.proto = "http"
    self.reason = reason
    self.tags = tags
    self.tags_old = tags_old
    self.exit_tags = exit_tags
    self.content = content
    self.content_exit = content_exit
    self.content_old = content_old

  def mark_false_positive(self):
    self.false_positive=True
    self.tags=self.move_file(self.tags,http_falsepositive_dir)
    self.tags_old=self.move_file(self.tags_old,http_falsepositive_dir)
    self.exit_tags=self.move_file(self.exit_tags,http_falsepositive_dir)
    self.content=self.move_file(self.content,http_falsepositive_dir)
    self.content_old=self.move_file(self.content_old, http_falsepositive_dir)
    self.content_exit=self.move_file(self.content_exit,http_falsepositive_dir)

  def remove_files(self):
    try: os.unlink(self.tags)
    except: pass
    try: os.unlink(self.tags_old)
    except: pass
    try: os.unlink(self.exit_tags)
    except: pass
    try: os.unlink(self.content)
    except: pass
    try: os.unlink(self.content_old)
    except: pass
    try: os.unlink(self.content_exit)
    except: pass

class SSHTestResult(TestResult):
  ''' Represents the result of an ssh test '''
  def __init__(self, exit_node, ssh_site, status):
    super(SSHTestResult, self).__init__(exit_node, ssh_site, status)
    self.proto = "ssh"

class DNSTestResult(TestResult):
  ''' Represents the result of a dns test '''
  def __init__(self, exit_node, dns_site, status):
    super(DNSTestResult, self).__init__(exit_node, dns_site, status)
    self.proto = "dns"

class DNSRebindTestResult(TestResult):
  ''' Represents the result of a dns rebind test '''
  def __init__(self, exit_node, dns_rebind_site, status):
    super(DNSRebindTestResult, self).__init__(exit_node, dns_rebind_site, status)
    self.proto = "dns"

class SMTPTestResult(TestResult):
  ''' Represents the result of an smtp test '''
  def __init__(self, exit_node, smtp_site, status):
    super(SMTPTestResult, self).__init__(exit_node, smtp_site, status)
    self.proto = "smtp"

class IMAPTestResult(TestResult):
  ''' Represents the result of an imap test '''
  def __init__(self, exit_node, imap_site, status):
    super(IMAPTestResult, self).__init__(exit_node, imap_site, status)
    self.proto = "imap"

class POPTestResult(TestResult):
  ''' Represents the result of a pop test '''
  def __init__(self, exit_node, pop_site, status):
    super(POPTestResult, self).__init__(exit_node, pop_site, status)
    self.proto = "pop"

class DataHandler:
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
    return self.__getResults(data_dir)

  def getSsh(self):
    ''' get results of ssh tests '''
    return self.__getResults(data_dir + 'ssh/')
    
  def getHttp(self):
    ''' get results of http tests '''
    return self.__getResults(data_dir + 'http/')

  def getSsl(self):
    ''' get results of ssl tests '''
    return self.__getResults(data_dir + 'ssl/')

  def getSmtp(self):
    ''' get results of smtp tests '''
    return self.__getResults(data_dir + 'smtp/')

  def getPop(self):
    ''' get results of pop tests '''
    return self.__getResults(data_dir + 'pop/')

  def getImap(self):
    ''' get results of imap tests '''
    return self.__getResults(data_dir + 'imap/')

  def getDns(self):
    ''' get results of basic dns tests '''
    return self.__getResults(data_dir + 'dns')

  def getDnsRebind(self):
    ''' get results of dns rebind tests '''
    return self.__getResults(data_dir + 'dnsbrebind/')

  def __getResults(self, dir):
    ''' 
    recursively traverse the directory tree starting with dir
    gather test results from files ending with .result
    '''
    results = []

    for root, dirs, files in os.walk(dir):
      for file in files:
        if file[:-41].endswith('result'):
          fh = open(os.path.join(root, file))
          result = pickle.load(fh)
          results.append(result)
    return results

  def safeFilename(self, str):
    ''' 
    remove characters illegal in some systems 
    and trim the string to a reasonable length
    '''
    replaced = (str.replace('/','_').replace('\\','_').replace('?','_').replace(':','_').
      replace('|','_').replace('*','_').replace('<','_').replace('>','_').replace('"',''))
    return replaced[:200]

  def saveResult(self, result):
    ''' generic method for saving test results '''
    address = ''
    if result.__class__.__name__ == 'HtmlTestResult' or result.__class__.__name__ == 'HttpTestResult':
      address = self.safeFilename(result.site[7:])
    elif result.__class__.__name__ == 'SSLTestResult':
      address = self.safeFilename(result.site[8:])
    elif 'TestResult' in result.__class__.__name__:
      address = self.safeFilename(result.site)
    else:
      raise Exception, 'This doesn\'t seems to be a result instance.'

    dir = data_dir+result.proto.lower()+'/'
    if result.status == TEST_SUCCESS:
      dir += 'successful/'
    if result.status == TEST_INCONCLUSIVE:
      dir += 'inconclusive/'
    if result.status == TEST_FAILURE:
      dir += 'failed/'
    
    result_file = open(dir+address+'.result.'+result.exit_node[1:], 'w')
    pickle.dump(result, result_file)
    result_file.close()

class SoupDiffer:
  """ Diff two soup tag sets, optionally writing diffs to outfile. """
  def __init__(self, soup_old, soup_new):
    self.soup_old = soup_old
    self.soup_new = soup_new

  def changed_tags(self):
    """ Return a list of tags changed or added to soup_new as strings """
    tags_old = sets.Set(map(str, 
           [tag for tag in self.soup_old.findAll() if isinstance(tag, Tag)]))
    tags_new = sets.Set(map(str, 
           [tag for tag in self.soup_new.findAll() if isinstance(tag, Tag)]))
    ret = list(tags_new - tags_old)
    ret.sort()
    return ret

  def changed_tags_with_attrs(self):
    """ Create a map of changed tags to ALL attributes that tag
        has ever had (changed or not) """
    changed_tags = {}
    for tags in map(BeautifulSoup, self.changed_tags()):
      for t in tags.findAll():
        if t.name not in changed_tags:
          changed_tags[t.name] = sets.Set([])
        for attr in t.attrs:
          changed_tags[t.name].add(attr[0])
    return changed_tags

  def has_more_changed_tags(self, tag_attr_map):
    """ Returns true if we have additional tags with additional
        attributes that were not present in tag_attr_map 
        (returned from changed_tags_with_attrs) """
    for tags in map(BeautifulSoup, self.changed_tags()):
      for t in tags.findAll():
        if t.name not in tag_attr_map:
          return True
        else:
          for attr in t.attrs:
            if attr[0] not in tag_attr_map[t.name]:
              return True
    return False

  def _get_attributes(self):
    attrs_old = [(tag.name, tag.attrs) for tag in self.soup_old.findAll()]
    attrs_new = [(tag.name, tag.attrs) for tag in self.soup_new.findAll()]
    attr_old = []
    for (tag, attr_list) in attrs_old:
      for attr in attr_list:
        attr_old.append((tag, attr)) 
    attr_new = []
    for (tag, attr_list) in attrs_new:
      for attr in attr_list:
        attr_old.append((tag, attr)) 
    return (attr_old, attr_new)
    
  def changed_attributes(self):
    """ Return a list of attributes added to soup_new """
    (attr_old, attr_new) = self._get_attributes()
    ret = list(sets.Set(attr_new) - sets.Set(attr_old))
    ret.sort()
    return ret

  def changed_attributes_by_tag(self):
    """ Transform the list of (tag, attribute) pairings for new/changed
        attributes into a map. This allows us to quickly see
        if any attributes changed for a specific tag. """
    changed_attributes = {}
    for (tag, attr) in self.changed_attributes():
      if tag not in changed_attributes:
        changed_attributes[tag] = sets.Set([])
      changed_attributes[tag].add(attr[0])
    return changed_attributes 

  def has_more_changed_attrs(self, attrs_by_tag):
    """ Returns true if we have any tags with additional
        changed attributes that were not present in attrs_by_tag
        (returned from changed_attributes_by_tag) """
    for (tag, attr) in self.changed_attributes():
      if tag in attrs_by_tag:
        if attr[0] not in attrs_by_tag[tag]:
          return True
      else:
        return True
    return False

  def changed_content(self):
    """ Return a list of tag contents changed in soup_new """
    tags_old = sets.Set(map(str, 
      [tag for tag in self.soup_old.findAll() if not isinstance(tag, Tag)]))
    tags_new = sets.Set(map(str, 
      [tag for tag in self.soup_new.findAll() if not isinstance(tag, Tag)]))
    ret = list(tags_new - tags_old)
    ret.sort()
    return ret

  def __str__(self):
    tags = self.changed_tags()
    out = "Tags:\n"+"\n".join(tags)
    attrs = self.changed_attributes()
    out += "\n\nAttrs:\n"
    for (tag, a) in attrs:
      out += a[0]+"="+a[1]+"\n"
    content = self.changed_content()
    out += "\n\nContent:\n"+"\n".join(map(str, content))
    return out

  def write_diff(self, outfile):
    f = open(outfile, "w")
    f.write(str(self))
    f.close()

class JSDiffer:
  # XXX: Strip html comments from these strings
  def __init__(self, js_string):
    if HAVE_PYPY: self.ast_cnts = self._count_ast_elements(js_string)

  def _ast_recursive_worker(ast, ast_cnts):
    if not ast.symbol in ast_cnts:
      ast_cnts[ast.symbol] = 1
    else: ast_cnts[ast.symbol] += 1
    if isinstance(ast, pypy.rlib.parsing.tree.Nonterminal):
      for child in ast.children:
        JSDiffer._ast_recursive_worker(child, ast_cnts)
  _ast_recursive_worker = Callable(_ast_recursive_worker)
 
  def _count_ast_elements(self, js_string, name="global"):
    ast_cnts = {}
    try:
      ast = pypy.lang.js.jsparser.parse(js_string)
      JSDiffer._ast_recursive_worker(ast, ast_cnts)
    except (pypy.rlib.parsing.deterministic.LexerError, UnicodeDecodeError, pypy.rlib.parsing.parsing.ParseError), e:
      # Store info about the name and type of parse error
      # so we can match that up too.
      name+=":"+e.__class__.__name__
      if "source_pos" in e.__dict__:
        name+=":"+str(e.source_pos)
      plog("INFO", "Parse error "+name+" on "+js_string)
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

  def prune_differences(self, other_string):
    if not HAVE_PYPY: return
    other_cnts = self._count_ast_elements(other_string)
    self._difference_pruner(other_cnts)

  def contains_differences(self, other_string):
    if not HAVE_PYPY:
      plog("NOTICE", "PyPy import not present. Not diffing javascript")
      return False
    other_cnts = self._count_ast_elements(other_string)
    return self._difference_checker(other_cnts) 

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
            script = str(child).replace("<!--", "").replace("-->", "")
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

  def prune_differences(self, other_soup):
    if not HAVE_PYPY: return
    other_cnts = self._count_ast_elements(other_soup)
    self._difference_pruner(other_cnts)

  def contains_differences(self, other_soup):
    if not HAVE_PYPY:
      plog("NOTICE", "PyPy import not present. Not diffing javascript")
      return False
    other_cnts = self._count_ast_elements(other_soup)
    return self._difference_checker(other_cnts) 
