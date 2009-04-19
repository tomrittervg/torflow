#!/usr/bin/python
import sys
import socket
import math

sys.path.append("../")
#from TorCtl import *
from TorCtl import TorUtil, PathSupport, TorCtl
from TorCtl.TorUtil import control_port, control_host, control_pass
from TorCtl.TorUtil import *
from TorCtl.PathSupport import *
import atexit

TorUtil.loglevel = "INFO"


def cleanup(c, f):
  print "Resetting FetchUselessDescriptors to "+f
  c.set_option("FetchUselessDescriptors", f) 
  

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((control_host,control_port))
c = Connection(s)
c.debug(file("control.log", "w"))
c.authenticate(control_pass)
FUDValue = c.get_option("FetchUselessDescriptors")[0][1]
c.set_option("FetchUselessDescriptors", "1") 
atexit.register(cleanup, *(c, FUDValue))
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
  nodes_up = 0.0000000005 # shhh. dirty hack for div 0 
  up = 0
  
  for r in sorted_rlist:
    if pct_rst.r_is_ok(r) and fast_rst.r_is_ok(r):
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

for i in xrange(0,100,3):
  check(i,i+3)

def check_entropy(rlist, clipping_point):
  clipped = 0
  clipped_bw = 0.0
  exits = 0
  nodes = 0
  bw = 0.0
  exit_bw = 0.0
  pure_entropy = 0.0
  clipped_entropy = 0.0
  uniform_entropy = 0.0

  guard_entropy = 0.0
  mid_entropy = 0.0
  exit_entropy = 0.0

  ggen = BwWeightedGenerator(rlist, FlagsRestriction(["Guard", "Fast", "Valid", "Running"]), 3, guard=True)
  mgen = BwWeightedGenerator(rlist, FlagsRestriction(["Valid", "Fast", "Running"]), 3)
  egen = BwWeightedGenerator(rlist, FlagsRestriction(["Exit", "Fast", "Valid", "Running"]), 3, exit=True)

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

  tgbw = ggen.total_weighted_bw
  tmbw = mgen.total_weighted_bw
  tebw = egen.total_weighted_bw
  
  for r in rlist:
    if not fast_rst.r_is_ok(r):
      continue
    if r.bw < 2:
      continue
    pure_entropy += (r.bw/bw)*math.log(r.bw/bw, 2)
    uniform_entropy += (1.0/nodes)*math.log(1.0/nodes, 2)
    gbw = r.bw
    mbw = r.bw
    ebw = r.bw
    if "Exit" in r.flags:
      gbw *= ggen.exit_weight
      mbw *= mgen.exit_weight
      ebw *= egen.exit_weight
    if "Guard" in r.flags:
      gbw *= ggen.guard_weight
      mbw *= mgen.guard_weight
      ebw *= egen.guard_weight

    if gbw/tgbw > 0: guard_entropy += (gbw/tgbw)*math.log(gbw/tgbw, 2)
    if mbw/tmbw > 0: mid_entropy += (mbw/tmbw)*math.log(mbw/tmbw, 2)
    if ebw/tebw > 0: exit_entropy += (ebw/tebw)*math.log(ebw/tebw, 2)
  
    rbw = 0
    if r.bw > clipping_point:
      rbw = clipping_point
    else:
      rbw = r.bw
    clipped_entropy += (rbw/clipped_bw)*math.log(rbw/clipped_bw, 2)
  
  print "Uniform entropy: " + str(-uniform_entropy)
  print "Raw entropy: " + str(-pure_entropy)
  print "Clipped entropy: " + str(-clipped_entropy)

  print "Guard entropy: " + str(-guard_entropy)
  print "Middle entropy: " + str(-mid_entropy)
  print "Exit entropy: " + str(-exit_entropy)

  print "Nodes: "+str(nodes)+", Exits: "+str(exits)+" Total bw: "+str(round(bw/(1024.0*1024),2))+", Exit Bw: "+str(round(exit_bw/(1024.0*1024),2))
  print "Clipped: "+str(clipped)+", bw: "+str(round(clipped_bw/(1024.0*1024),2))


check_entropy(sorted_rlist, 1500000)
