#!/usr/bin/python

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


def main(argv):
  dh = DataHandler()
  # FIXME: Handle this better.. maybe explicit --file or --exit options?
  # For now, I should be the only one runnin this so...
  # XXX: Also want to filter on reason, false positive, and
  # failure/inconclusive
  if len(argv) == 1:
    results = dh.getAll()
  elif argv[1][0] == '$':
    results = dh.filterByNode(dh.getAll(), argv[1])
  else:
    results = [dh.getResult(argv[1])]

  for r in results:
    r.verbose = True
    if r.status == TEST_FAILURE and r.reason == "FailureExitOnly":
      print r
      print "\n-----------------------------\n"

if __name__ == "__main__":
  main(sys.argv)
