#!/usr/bin/python

import dircache
import operator
import os
import pickle
import sys
import time

import sets
from sets import Set

import getopt

import libsoat
from libsoat import *

sys.path.append("../")

import TorCtl.TorUtil
from TorCtl.TorUtil import *

TorCtl.TorUtil.loglevel="NOTICE"

def usage(argv):
  print "Usage: "+argv[0]+" with 0 or more of the following filters: "
  print "  --dir <datadir>"
  print "  --file <.result file>"
  print "  --exit <idhex>"
  print "  --reason <soat failure reason>"
  print "  --proto <protocol>"
  print "  --resultfilter <TestResult class name>"
  print "  --statuscode <'Failure' or 'Inconclusive'>"
  print "  --verbose"
  sys.exit(1)

def getargs(argv):
  try:
    opts,args = getopt.getopt(argv[1:],"d:f:e:r:vt:p:s:", 
             ["dir=", "file=", "exit=", "reason=", "resultfilter=", "proto=", 
              "verbose", "statuscode="])
  except getopt.GetoptError,err:
    print str(err)
    usage(argv)
  use_dir="./data/"
  use_file=None
  node=None
  reason=None
  result=2
  verbose=1
  proto=None
  resultfilter=None
  for o,a in opts:
    if o == '-d' or o == '--dir':
      use_dir = a
    elif o == '-f' or o == '--file':
      use_file = a
    elif o == '-e' or o == '--exit': 
      node = a
    elif o == '-r' or o == '--reason': 
      reason = a
    elif o == '-v' or o == '--verbose': 
      verbose += 1
    elif o == '-t' or o == '--resultfilter':
      resultfilter = a
    elif o == '-p' or o == '--proto':
      proto = a
    elif o == '-s' or o == '--statuscode': 
      try:
        result = int(a)
      except ValueError:
        result = RESULT_CODES[a]
  return use_dir,use_file,node,reason,result,verbose,resultfilter,proto
 
def main(argv):
  use_dir,use_file,node,reason,result,verbose,resultfilter,proto=getargs(argv)
  dh = DataHandler(use_dir)
  print dh.data_dir

  if use_file:
    results = [dh.getResult(use_file)]
  elif node:
    results = dh.filterByNode(dh.getAll(), node)
  else:
    results = dh.getAll()

  for r in results:
    r.verbose = verbose
    if (not result or r.status == result) and \
       (not reason or r.reason == reason) and \
       (not proto or r.proto == proto) and \
       (not resultfilter or r.__class__.__name__ == resultfilter):
      try:
        print r
      except IOError, e:
        traceback.print_exc()
      print "\n-----------------------------\n"

if __name__ == "__main__":
  main(sys.argv)
