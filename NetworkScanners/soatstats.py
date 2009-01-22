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
  inconclusive_nodes.sort(lambda x, y: cmp(y.total.inconclusive, y.total.inconclusive))

  # Sort by individual test counts, print out nodes with highest counts first

if __name__ == "__main__":
  main(sys.argv)
