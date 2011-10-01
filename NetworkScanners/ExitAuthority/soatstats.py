#!/usr/bin/python
#
# 2008 Aleksei Gorny, mentored by Mike Perry

import dircache
import operator
import os
import pickle
import sys
import time

if sys.version_info < (2, 5):
    from sets import Set as set

import libsoat
from libsoat import *

sys.path.append("../../")
try:
    from TorCtl.TorUtil import *
except ImportError:
    from os import getcwd, path
    print "TorCtl not found in %s" % path.abspath(getcwd()+'../..')
    print "Exiting..."
    exit()   

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

  reason_counts = {}
  nodeResults = {}
  tests = set([])

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
      if result.reason not in reason_counts:
        reason_counts[result.reason] = 1
      else:
        reason_counts[result.reason] += 1
    
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

  #print "\nInconclusive test results"
  #for node in inconclusive_nodes:
  #  if node.total.inconclusive != 0:
  #    print `node.idhex` + "\t" + `node.total.inconclusive`

  for test in tests:
    print "\n" + test[:(-6)] + " failures"
    for node in failed_nodes_specific[test]:
      if node.counts[test].bad != 0:
        print `node.idhex` + "\t" + `node.counts[test].bad`

  #for test in tests:
  #  print "\n" + test[:(-6)] + " inconclusive results"
  #  for node in inconclusive_nodes_specific[test]:
  #    if node.counts[test].inconclusive != 0:
  #      print `node.idhex` + "\t" + `node.counts[test].inconclusive`

  print ""

  reasons = sorted(reason_counts.iterkeys(), lambda x, y:
cmp(reason_counts[x], reason_counts[y]))

  for r in reasons:
    print r+": "+str(reason_counts[r])

if __name__ == "__main__":
  main(sys.argv)
