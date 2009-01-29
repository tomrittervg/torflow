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
      new_vs_old = SoupDiffer(BeautifulSoup(open(result.tags, "r").read()), 
                BeautifulSoup(open(result.tags_old, 
                               "r").read()))
      old_vs_new = SoupDiffer(BeautifulSoup(open(result.tags_old, "r").read()), 
                BeautifulSoup(open(result.tags, 
                               "r").read()))
      new_vs_tor = SoupDiffer(BeautifulSoup(open(result.tags, "r").read()), 
                BeautifulSoup(open(result.exit_tags, 
                               "r").read()))
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
 
      print false_positive      

  print ""

if __name__ == "__main__":
  main(sys.argv)
