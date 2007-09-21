#!/usr/bin/python
import sys
import socket
import math
#from TorCtl import *
from TorCtl import TorUtil, PathSupport, TorCtl
from TorCtl.TorUtil import *
from TorCtl.PathSupport import *

TorUtil.loglevel = "NOTICE"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1",9061))
c = Connection(s)
c.debug(file("control.log", "w"))
c.authenticate()
nslist = c.get_network_status()
sorted_rlist = c.read_routers(c.get_network_status())

sorted_rlist.sort(lambda x, y: cmp(y.bw, x.bw))
for i in xrange(len(sorted_rlist)): sorted_rlist[i].list_rank = i

fast_rst = FlagsRestriction(["Fast"], [])
exit_rst = FlagsRestriction(["Exit"], [])
dir_rst = FlagsRestriction(["V2Dir"], [])
heavy_exits = OrNodeRestriction(
      [ExitPolicyRestriction("255.255.255.255", 6881),
      ExitPolicyRestriction("255.255.255.255", 6889),
      ExitPolicyRestriction("255.255.255.255", 6346),
      ExitPolicyRestriction("255.255.255.255", 25)])


def check(start, stop):
  pct_rst = PercentileRestriction(start, stop, sorted_rlist)
  bw = 0
  nodes = 0
  exits = 0
  exit_bw = 0
  heavy = 0
  dirs = 0
  nodes_up = 0
  up = 0
  
  for r in sorted_rlist:
    if pct_rst.r_is_ok(r):
      nodes += 1
      bw += r.bw
      if r.uptime > 0:
        nodes_up += 1.0
        up += r.uptime
      if exit_rst.r_is_ok(r):
        exits += 1
        exit_bw += r.bw
      if heavy_exits.r_is_ok(r):
        heavy += 1
      if dir_rst.r_is_ok(r):
        dirs += 1
  
  print str(start)+"-"+str(stop)+": N: "+str(nodes)+", Bw: "+str(round(bw/(1024*1024.0), 2))+", X: "+str(exits)+", XBw: "+str(round(exit_bw/(1024*1024.0),2))+", BT: "+str(heavy)+", Dirs:"+str(dirs)+", Up: "+str(round(up/nodes_up/60/60/24, 2))

for i in xrange(0,80,5):
  check(i,i+5)

def check_entropy(rlist, clipping_point):
  clipped = 0
  clipped_bw = 0.0
  exits = 0
  nodes = 0
  bw = 0.0
  exit_bw = 0.0
  pure_entropy = 0.0
  clipped_entropy = 0.0
  for r in rlist:
    if not fast_rst.r_is_ok(r):
      continue
    if r.bw > clipping_point:
      clipped += 1
      clipped_bw += clipping_point
    else:
      clipped_bw += r.bw
    nodes += 1
    bw += r.bw
    if exit_rst.r_is_ok(r):
      exits += 1
      exit_bw += r.bw
  
  for r in rlist:
    if not fast_rst.r_is_ok(r):
      continue
    if r.bw < 2:
      continue
    pure_entropy += (r.bw/bw)*math.log(r.bw/bw, 2)
  
    rbw = 0
    if r.bw > clipping_point:
      rbw = clipping_point
    else:
      rbw = r.bw
    clipped_entropy += (rbw/clipped_bw)*math.log(rbw/clipped_bw, 2)
  
  print "Raw entropy: " + str(-pure_entropy)
  print "Clipped entropy: " + str(-clipped_entropy)
  print "Nodes: "+str(nodes)+", Exits: "+str(exits)+" Total bw: "+str(round(bw/(1024.0*1024),2))+", Exit Bw: "+str(round(exit_bw/(1024.0*1024),2))
  print "Clipped: "+str(clipped)+", bw: "+str(round(clipped_bw/(1024.0*1024),2))


check_entropy(sorted_rlist, 1500000)
