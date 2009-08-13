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

TorCtl.TorUtil.loglevel="INFO"

if TorCtl.TorUtil.loglevels[TorCtl.TorUtil.loglevel] > TorCtl.TorUtil.loglevels["INFO"]:
  # Kill stderr (jsdiffer and exception noise) if our loglevel is above INFO
  sys.stderr = file("/dev/null", "w")


def usage(argv):
  print "Usage: "+argv[0]+" with 0 or more of the following filters: "
  print "  --dir <datadir>"
  print "  --file <.result file>"
  print "  --exit <idhex>"
  print "  --before <timestamp as string>"
  print "  --after <timestamp as string>"
  print "  --reason <soat failure reason>    # may be repeated"
  print "  --noreason <soat failure reason>  # may be repeated"
  print "  --proto <protocol>"
  print "  --resultfilter <TestResult class name>"
  print "  --statuscode <'Failure' or 'Inconclusive'>"
  print "  --sortby <'proto' or 'url' or 'exit' or 'reason'>"
  print "  --falsepositives"
  print "  --verbose"
  sys.exit(1)

def getargs(argv):
  try:
    opts,args = getopt.getopt(argv[1:],"d:f:e:r:vt:p:s:o:n:a:b:F", 
             ["dir=", "file=", "exit=", "reason=", "resultfilter=", "proto=", 
              "verbose", "statuscode=", "sortby=", "noreason=", "after=",
              "before=", "falsepositives"])
  except getopt.GetoptError,err:
    print str(err)
    usage(argv)
  # FIXME: make all these repeatable
  use_dir="./data/"
  use_file=None
  node=None
  reasons=[]
  noreasons=[]
  result=2
  verbose=1
  proto=None
  resultfilter=None
  before = 0xffffffff
  after = 0
  sortby="proto"
  falsepositives=False
  for o,a in opts:
    if o == '-d' or o == '--dir':
      use_dir = a
    elif o == '-f' or o == '--file':
      use_file = a
    elif o == '-b' or o == '--before':
      before = time.mktime(time.strptime(a))
    elif o == '-a' or o == '--after': 
      after = time.mktime(time.strptime(a))
    elif o == '-r' or o == '--reason': 
      reasons.append(a)
    elif o == '-r' or o == '--noreason': 
      noreasons.append(a)
    elif o == '-v' or o == '--verbose': 
      verbose += 1
    elif o == '-t' or o == '--resultfilter':
      resultfilter = a
    elif o == '-p' or o == '--proto':
      proto = a
    elif o == '-F' or o == '--falsepositives':
      falsepositives = True
    elif o == '-s' or o == '--sortby': 
      if a not in ["proto", "site", "exit", "reason"]:
        usage(argv)
      else: sortby = a 
    elif o == '-s' or o == '--statuscode': 
      try:
        result = int(a)
      except ValueError:
        result = RESULT_CODES[a]
  return use_dir,use_file,node,reasons,noreasons,result,verbose,resultfilter,proto,sortby,before,after,falsepositives
 
def main(argv):
  use_dir,use_file,node,reasons,noreasons,result,verbose,resultfilter,proto,sortby,before,after,falsepositives=getargs(argv)
  dh = DataHandler(use_dir)
  print dh.data_dir

  if use_file:
    results = [dh.getResult(use_file)]
  elif node:
    results = dh.filterByNode(dh.getAll(), "$"+node)
  else:
    results = dh.getAll()

  if sortby == "url":
    results.sort(lambda x, y: cmp(x.site, y.site))
  elif sortby == "reason":
    results.sort(lambda x, y: cmp(x.reason, y.reason))
  elif sortby == "exit":
    results.sort(lambda x, y: cmp(x.exit_node, y.exit_node))

  for r in results:
    r.verbose = verbose
    if r.reason in noreasons: continue
    if reasons and r.reason not in reasons: continue
    if r.timestamp < after or before < r.timestamp: continue
    if (falsepositives) ^ r.false_positive: continue
    if (not result or r.status == result) and \
       (not proto or r.proto == proto) and \
       (not resultfilter or r.__class__.__name__ == resultfilter):
      try:
        print r
      except KeyboardInterrupt:
        raise KeyboardInterrupt
      except IOError, e:
        traceback.print_exc()
      except Exception, e:
        traceback.print_exc()
      print "\n-----------------------------\n"

if __name__ == "__main__":
  main(sys.argv)
