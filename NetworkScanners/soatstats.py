#!/usr/bin/python
#
# 2008 Aleksei Gorny, mentored by Mike Perry

import dircache
import operator
import os
import pickle
import sys
import time

import sets
from sets import Set

import libsoat
from libsoat import *

sys.path.append("../")
from TorCtl.TorUtil import *

sys.path.append("./libs/pypy-svn/")
import pypy.rlib.parsing.parsing
import pypy.lang.js.jsparser

attrs_with_raw_script = [
'onabort', 'onactivate', 'onafterprint', 'onafterupdate',
'onattrmodified', 'onbeforeactivate', 'onbeforecopy', 'onbeforecut',
'onbeforedeactivate', 'onbeforeeditfocus', 'onbeforepaste', 'onbeforeprint',
'onbeforeunload', 'onbeforeupdate', 'onblur', 'onbounce', 'onbroadcast',
'oncellchange', 'onchange', 'oncharacterdatamodified', 'onclick', 'onclose',
'oncommand', 'oncommandupdate', 'oncontextmenu', 'oncontrolselect', 'oncopy',
'oncut', 'ondataavaible', 'ondataavailable', 'ondatasetchanged',
'ondatasetcomplete', 'ondblclick', 'ondeactivate', 'ondrag', 'ondragdrop',
'ondragend', 'ondragenter', 'ondragexit', 'ondraggesture', 'ondragleave',
'ondragover', 'ondragstart', 'ondrop', 'onerror', 'onerrorupdate',
'onfilterchange', 'onfilterupdate', 'onfinish', 'onfocus', 'onfocusin',
'onfocusout', 'onhelp', 'oninput', 'onkeydown', 'onkeypress', 'onkeyup',
'onlayoutcomplete', 'onload', 'onlosecapture', 'onmousedown', 'onmouseenter',
'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup',
'onmousewheel', 'onmove', 'onmoveend', 'onmoveout', 'onmovestart',
'onnodeinserted', 'onnodeinsertedintodocument', 'onnoderemoved',
'onnoderemovedfromdocument', 'onoverflowchanged', 'onpaint', 'onpaste',
'onpopupHidden', 'onpopupHiding', 'onpopupShowing', 'onpopupShown',
'onpropertychange', 'onreadystatechange', 'onreset', 'onresize',
'onresizeend', 'onresizestart', 'onrowenter', 'onrowexit', 'onrowsdelete',
'onrowsinserted', 'onscroll', 'onselect', 'onselectionchange',
'onselectstart', 'onstart', 'onstop', 'onsubmit', 'onsubtreemodified',
'ontext', 'onunderflow', 'onunload' 
]
attrs_to_check = ['background', 'cite', 'classid', 'codebase', 'data',
'longdesc', 'profile', 'src', 'style', 'usemap']
attrs_to_check.extend(attrs_with_raw_script)
attrs_to_check_map = {}
for __a in attrs_to_check: attrs_to_check_map[__a]=1
attrs_with_raw_script_map = {}
for __a in attrs_with_raw_script: attrs_with_raw_script_map[__a]=1


class ResultCount:
  def __init__(self, type):
    self.type = type
    self.good = 0
    self.bad = 0
    self.inconclusive = 0

class ResultNode:
  def __init__(self, idhex):
    self.total = ResultCount("All")
    self.counts = {}
    self.idhex = idhex 

def main(argv):
  dh = DataHandler()
  data = dh.getAll()

  nodeResults = {}
  tests = Set([])

  total = len(data)

  for result in data:
    if result.exit_node in nodeResults:
      rn = nodeResults[result.exit_node]
    else:
      rn = ResultNode(result.exit_node)
      nodeResults[result.exit_node] = rn

    tests.add(result.__class__.__name__) 
    if result.__class__.__name__ not in rn.counts:
      rn.counts[result.__class__.__name__] = ResultCount(result.__class__.__name__)

    if result.status == TEST_SUCCESS:
      rn.total.good += 1
      rn.counts[result.__class__.__name__].good += 1
    elif result.status == TEST_INCONCLUSIVE:
      rn.total.inconclusive += 1
      rn.counts[result.__class__.__name__].inconclusive += 1
    elif result.status == TEST_FAILURE:
      rn.total.bad += 1
      rn.counts[result.__class__.__name__].bad += 1
    
  # Sort by total counts, print out nodes with highest counts first
  failed_nodes = nodeResults.values()
  failed_nodes.sort(lambda x, y: cmp(y.total.bad, x.total.bad))

  inconclusive_nodes = nodeResults.values()
  inconclusive_nodes.sort(lambda x, y: cmp(y.total.inconclusive, x.total.inconclusive))

  # Sort by individual test counts, print out nodes with highest counts first

  failed_nodes_specific = {}
  inconclusive_nodes_specific = {}
  for test in tests:
    tested = [node for node in nodeResults.values() if node.counts.get(test)]
    failed_nodes_specific[test] = list(sorted(tested, lambda x, y: cmp(y.counts[test].bad, x.counts[test].bad)))
    inconclusive_nodes_specific[test] = list(sorted(tested, lambda x, y: cmp(y.counts[test].inconclusive, x.counts[test].inconclusive)))

  print "\nFailures"
  for node in failed_nodes:
    if node.total.bad != 0:
      print `node.idhex` + "\t" + `node.total.bad`

  print "\nInconclusive test results"
  for node in inconclusive_nodes:
    if node.total.inconclusive != 0:
      print `node.idhex` + "\t" + `node.total.inconclusive`

  for test in tests:
    print "\n" + test[:(-6)] + " failures"
    for node in failed_nodes_specific[test]:
      if node.counts[test].bad != 0:
        print `node.idhex` + "\t" + `node.counts[test].bad`

  for test in tests:
    print "\n" + test[:(-6)] + " inconclusive results"
    for node in inconclusive_nodes_specific[test]:
      if node.counts[test].inconclusive != 0:
        print `node.idhex` + "\t" + `node.counts[test].inconclusive`


  # False positive test left in for verifcation and tweaking
  # TODO: Remove this bit eventually
  for result in data:
    if result.__class__.__name__ == "HtmlTestResult":
      if not result.tags_old or not result.tags or not result.exit_tags:
        continue
      print result.exit_node

      print result.tags
      print result.tags_old
      print result.exit_tags

      new_soup = BeautifulSoup(open(result.tags, "r").read())
      old_soup = BeautifulSoup(open(result.tags_old, "r").read())
      tor_soup = BeautifulSoup(open(result.exit_tags, "r").read())

      new_vs_old = SoupDiffer(new_soup, old_soup)
      old_vs_new = SoupDiffer(old_soup, new_soup)
      new_vs_tor = SoupDiffer(new_soup, tor_soup)

      changed_tags = {}
      changed_attributes = {}
      # I'm an evil man and I'm going to CPU hell..
      for tags in map(BeautifulSoup, old_vs_new.changed_tags()):
        for t in tags.findAll():
          if t.name not in changed_tags:
            changed_tags[t.name] = sets.Set([])
          for attr in t.attrs:
            changed_tags[t.name].add(attr[0])
      for tags in map(BeautifulSoup, new_vs_old.changed_tags()):
        for t in tags.findAll():
          if t.name not in changed_tags:
            changed_tags[t.name] = sets.Set([])
          for attr in t.attrs:
            changed_tags[t.name].add(attr[0])
      for (tag, attr) in old_vs_new.changed_attributes():
        if tag not in changed_attributes:
          changed_attributes[tag] = {}
        changed_attributes[tag][attr[0]] = 1 
      for (tag, attr) in new_vs_old.changed_attributes():
        changed_attributes[attr[0]] = 1 
        if tag not in changed_attributes:
          changed_attributes[tag] = {}
        changed_attributes[tag][attr[0]] = 1 
      
      changed_content = bool(old_vs_new.changed_content() or old_vs_new.changed_content())
  
      false_positive = True 
      for tags in map(BeautifulSoup, new_vs_tor.changed_tags()):
        for t in tags.findAll():
          if t.name not in changed_tags:
            false_positive = False
          else:
             for attr in t.attrs:
               if attr[0] not in changed_tags[t.name]:
                 false_positive = False
      for (tag, attr) in new_vs_tor.changed_attributes():
        if tag in changed_attributes:
          if attr[0] not in changed_attributes[tag]:
            false_positive=False
        else:
          if not false_positive:
            plog("ERROR", "False positive contradiction at "+exit_node+" for "+address)
            false_positive = False
  
      if new_vs_tor.changed_content() and not changed_content:
        false_positive = False
  
      def ast_recurse(ast, map):
        if not ast.symbol in map:
          map[ast.symbol] = 1
        else: map[ast.symbol] += 1
        if isinstance(ast, pypy.rlib.parsing.tree.Nonterminal):
          for child in ast.children:
            ast_recurse(child, map)
  
      def count_ast(map, tags):
        for tag_l in tags: 
          for tag in tag_l.findAll():
            did_parse = False
            if tag.name == 'script':
              for child in tag.childGenerator():
                if isinstance(child, Tag):
                  plog("ERROR", "Script tag with subtag!")
                else:
                  try:
                    did_parse = True
                    ast = pypy.lang.js.jsparser.parse(str(child))
                    ast_recurse(ast, map)
                  except (pypy.rlib.parsing.deterministic.LexerError, UnicodeDecodeError, pypy.rlib.parsing.parsing.ParseError):
                    plog("NOTICE", "Parse error on "+str(child))
                    if not "ParseError"+tag.name in map:
                      map["ParseError"+tag.name] = 1
                    else: map["ParseError"+tag.name] +=1 
               
            for attr in tag.attrs:
              # XXX: %-encoding too
              parse = ""
              if attr[1].replace(" ","")[:11] == "javascript:":
                split_at = attr[1].find(":")+1
                parse = str(attr[1][split_at:])
              elif attr[0] in attrs_with_raw_script_map:
                parse = str(attr[1])
              if not parse: continue
              try:
                did_parse = True
                ast = pypy.lang.js.jsparser.parse(parse)
                ast_recurse(ast, map)
              except (pypy.rlib.parsing.deterministic.LexerError, UnicodeDecodeError, pypy.rlib.parsing.parsing.ParseError):
                plog("NOTICE", "Parse error on "+parse+" in "+attr[0]+"="+attr[1])
                if not "ParseError"+tag.name+attr[0] in map:
                  map["ParseError"+tag.name+attr[0]] = 1
                else: map["ParseError"+attr[0]] +=1

      if false_positive:
        # Use http://codespeak.net/pypy/dist/pypy/lang/js/ to parse
        # links and attributes that contain javascript
  
        old_vs_new_cnt = {}
        count_ast(old_vs_new_cnt, [old_soup])
 
        new_vs_old_cnt = {}
        count_ast(new_vs_old_cnt, [new_soup])
  
        # for each changed tag, count all tree elements in a hash table.
        # Then, compare the counts between the two fetches
        # If any count changes, mark its count as -1
        # Make sure the terminal counts of the tor fetch match
        # except for the -1 terminals
  
        for node in old_vs_new_cnt.iterkeys():
          if node not in new_vs_old_cnt:
            plog("INFO", "Javascript AST element "+node+" absent..")
            new_vs_old_cnt[node] = 0
          elif new_vs_old_cnt[node] != old_vs_new_cnt[node]:
            plog("INFO", "Javascript AST count differs for "+node+": "+str(new_vs_old_cnt[node])+" vs "+str(old_vs_new_cnt[node]))
            new_vs_old_cnt[node] = 0

        for node in new_vs_old_cnt.iterkeys():
          if node not in old_vs_new_cnt:
            plog("INFO", "Javascript AST element "+node+" absent..")
            new_vs_old_cnt[node] = 0
        
        new_vs_tor_cnt = {} 
        count_ast(new_vs_tor_cnt, [tor_soup])
  
        for node in new_vs_old_cnt.iterkeys():
          if not new_vs_old_cnt[node]:
            continue
          if node not in new_vs_tor_cnt:
            plog("ERROR", "Javascript AST element "+node+" absent from Tor.")
            false_positive = False
          elif new_vs_old_cnt[node] != new_vs_tor_cnt[node]:
            plog("ERROR", "Javascript AST count differs for "+node+": "+str(new_vs_old_cnt[node])+" vs "+str(new_vs_tor_cnt[node]))
            false_positive = False
        
        for node in new_vs_tor_cnt.iterkeys():
          if node not in new_vs_old_cnt:
            plog("ERROR", "Javascript AST element "+node+" present only in Tor")
            false_positive = False

 
      print false_positive      

  print ""

if __name__ == "__main__":
  main(sys.argv)
