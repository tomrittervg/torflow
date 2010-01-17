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

TorUtil.loglevel = "WARN"

# TODO:
#  Print ratios of All, Guard, Mid, Exit and Guard+Exit nodes
#    - Print Num < 1, Num >= 1, avg < 1, avg >= 1, and avg for each

def cleanup(c, f):
  print "Resetting FetchUselessDescriptors to "+f
  c.set_option("FetchUselessDescriptors", f) 
  

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((control_host,control_port))
c = Connection(s)
c.debug(file("control.log", "w"))
c.authenticate(control_pass)
#c.authenticate_cookie(file("/home/torperf/tor-data1/control_auth_cookie", "r"))
FUDValue = c.get_option("FetchUselessDescriptors")[0][1]
c.set_option("FetchUselessDescriptors", "1") 
atexit.register(cleanup, *(c, FUDValue))
nslist = c.get_network_status()
sorted_rlist = c.read_routers(c.get_network_status())

sorted_rlist.sort(lambda x, y: cmp(y.bw, x.bw))
for i in xrange(len(sorted_rlist)): sorted_rlist[i].list_rank = i

mid_rst = FlagsRestriction([], ["Exit", "Guard"])
nmid_rst = PathSupport.OrNodeRestriction(
          [
  PathSupport.FlagsRestriction(mandatory=["Guard"], forbidden=[]),
  PathSupport.FlagsRestriction(mandatory=["Exit"], forbidden=[])
          ]
                        )

bw_limit_rst = RateLimitedRestriction(True)
nbw_limit_rst = RateLimitedRestriction(False)

win_rst = PathSupport.OSRestriction(ok=["Win"])
nwin_rst = PathSupport.OSRestriction(ok=[], bad=["Win"])

v2dir_rst = PathSupport.FlagsRestriction(["V2Dir"])
nv2dir_rst = PathSupport.FlagsRestriction([],["V2Dir"])

win_mid = NodeRestrictionList([mid_rst, win_rst])
win_nmid = NodeRestrictionList([nmid_rst, win_rst])

v2dir_mid = NodeRestrictionList([mid_rst, v2dir_rst])
nv2dir_mid = NodeRestrictionList([mid_rst, nv2dir_rst])


nbw_limit_mid = NodeRestrictionList([mid_rst, nbw_limit_rst])
nbw_limit_nmid = NodeRestrictionList([nmid_rst, nbw_limit_rst])

win_nltd = NodeRestrictionList([nbw_limit_rst, win_rst])
nwin_nltd = NodeRestrictionList([nbw_limit_rst, nwin_rst])

super_bad = OrNodeRestriction([win_rst, nbw_limit_rst])

# >= 0.2.2.2-alpha and >= 0.2.1.20
cwind_yes = NodeRestrictionList([VersionRangeRestriction("0.2.1.20"),
             NotNodeRestriction(VersionRangeRestriction("0.2.2.0", "0.2.2.1"))])
cwind_no = NotNodeRestriction(cwind_yes)

nsbw_yes = VersionRangeRestriction("0.2.1.17")
nsbw_no = NotNodeRestriction(nsbw_yes)


fast_rst = FlagsRestriction(["Fast"], [])
#exit_rst = NodeRestrictionList([cwind_yes, FlagsRestriction(["Exit"], [])])
exit_rst = FlagsRestriction(["Exit"], [])
exitonly_rst = FlagsRestriction(["Exit"], ["Guard"])
guardonly_rst = FlagsRestriction(["Guard"], ["Exit"])
guardexit_rst = FlagsRestriction(["Guard", "Exit"], [])
mid_rst = FlagsRestriction([], ["Guard", "Exit"])
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
  pct_list = []

  for r in sorted_rlist:
    if pct_rst.r_is_ok(r) and fast_rst.r_is_ok(r):
      nodes += 1
      bw += r.bw
      pct_list.append(r)

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

  check_ratios(pct_list)


def check_entropy(rlist, clipping_point):
  clipped = 0
  clipped_bw = 0.0
  exits = 0
  nodes = 0
  bw = 0.0
  desc_bw = 0.0
  exit_bw = 0.0
  pure_entropy = 0.0
  desc_entropy = 0.0
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
    desc_bw += r.desc_bw
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
    desc_entropy += (r.desc_bw/desc_bw)*math.log(r.desc_bw/desc_bw, 2)
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
    if r.desc_bw > clipping_point:
      rbw = clipping_point
    else:
      rbw = r.desc_bw
    clipped_entropy += (rbw/clipped_bw)*math.log(rbw/clipped_bw, 2)

  print ""
  print "Uniform entropy: " + str(-uniform_entropy)
  print "Consensus entropy: " + str(-pure_entropy)
  print "Raw Descriptor entropy: " + str(-desc_entropy)
  print "Clipped Descriptor entropy: " + str(-clipped_entropy)

  print "Consensus Guard entropy: " + str(-guard_entropy)
  print "Consensus Middle entropy: " + str(-mid_entropy)
  print "Consensus Exit entropy: " + str(-exit_entropy)

  print "Nodes: "+str(nodes)+", Exits: "+str(exits)+" Total bw: "+str(round(bw/(1024.0*1024),2))+", Exit Bw: "+str(round(exit_bw/(1024.0*1024),2))
  print "Clipped: "+str(clipped)+", bw: "+str(round(clipped_bw/(1024.0*1024),2))
  print ""


class RatioStats:
  def __init__(self):
    self.avg = 0
    self.avg_lt1 = 0
    self.avg_gt1 = 0
    self.cnt = 0
    self.cnt_lt1 = 0
    self.cnt_gt1 = 0
    self.pct_lt1 = 0
    self.pct_gt1 = 0

def check_ratios(sorted_rlist):
  # ratio stats
  all_ratio = RatioStats()
  guard_ratio = RatioStats()
  mid_ratio = RatioStats()
  exit_ratio = RatioStats()
  guardexit_ratio = RatioStats()

  for r in sorted_rlist:
    if r.down or r.desc_bw <= 0: continue
    ratio = float(r.bw)/r.desc_bw
    if ratio >= 1:
      rc_gt1 = 1
      rc_lt1 = 0
      r_gt1 = ratio
      r_lt1 = 0
    else:
      rc_gt1 = 0
      rc_lt1 = 1
      r_gt1 = 0
      r_lt1 = ratio

    all_ratio.cnt += 1
    all_ratio.cnt_lt1 += rc_lt1
    all_ratio.cnt_gt1 += rc_gt1
    all_ratio.avg += ratio
    all_ratio.avg_lt1 += r_lt1
    all_ratio.avg_gt1 += r_gt1

    if guardonly_rst.r_is_ok(r):
      guard_ratio.avg += ratio
      guard_ratio.avg_lt1 += r_lt1
      guard_ratio.avg_gt1 += r_gt1
      guard_ratio.cnt += 1
      guard_ratio.cnt_lt1 += rc_lt1
      guard_ratio.cnt_gt1 += rc_gt1
    if guardexit_rst.r_is_ok(r):
      guardexit_ratio.avg += ratio
      guardexit_ratio.avg_lt1 += r_lt1
      guardexit_ratio.avg_gt1 += r_gt1
      guardexit_ratio.cnt += 1
      guardexit_ratio.cnt_lt1 += rc_lt1
      guardexit_ratio.cnt_gt1 += rc_gt1
    if exitonly_rst.r_is_ok(r):
      exit_ratio.avg += ratio
      exit_ratio.avg_lt1 += r_lt1
      exit_ratio.avg_gt1 += r_gt1
      exit_ratio.cnt += 1
      exit_ratio.cnt_lt1 += rc_lt1
      exit_ratio.cnt_gt1 += rc_gt1
    if mid_rst.r_is_ok(r):
      mid_ratio.avg += ratio
      mid_ratio.avg_lt1 += r_lt1
      mid_ratio.avg_gt1 += r_gt1
      mid_ratio.cnt += 1
      mid_ratio.cnt_lt1 += rc_lt1
      mid_ratio.cnt_gt1 += rc_gt1

  if not all_ratio.cnt:     all_ratio.cnt = -1
  if not all_ratio.cnt_lt1: all_ratio.cnt_lt1 = -1
  if not all_ratio.cnt_gt1: all_ratio.cnt_gt1 = -1

  all_ratio.avg     /= all_ratio.cnt
  all_ratio.avg_lt1 /= all_ratio.cnt_lt1
  all_ratio.avg_gt1 /= all_ratio.cnt_gt1
  all_ratio.pct_lt1 = round((100.0*all_ratio.cnt_lt1)/all_ratio.cnt,1)
  all_ratio.pct_gt1 = round((100.0*all_ratio.cnt_gt1)/all_ratio.cnt,1)

  if not guard_ratio.cnt:     guard_ratio.cnt = -1
  if not guard_ratio.cnt_lt1: guard_ratio.cnt_lt1 = -1
  if not guard_ratio.cnt_gt1: guard_ratio.cnt_gt1 = -1

  guard_ratio.avg     /= guard_ratio.cnt
  guard_ratio.avg_lt1 /= guard_ratio.cnt_lt1
  guard_ratio.avg_gt1 /= guard_ratio.cnt_gt1
  guard_ratio.pct_lt1 = round((100.0*guard_ratio.cnt_lt1)/guard_ratio.cnt,1)
  guard_ratio.pct_gt1 = round((100.0*guard_ratio.cnt_gt1)/guard_ratio.cnt,1)

  if not mid_ratio.cnt:     mid_ratio.cnt = -1
  if not mid_ratio.cnt_lt1: mid_ratio.cnt_lt1 = -1
  if not mid_ratio.cnt_gt1: mid_ratio.cnt_gt1 = -1

  mid_ratio.avg     /= mid_ratio.cnt
  mid_ratio.avg_lt1 /= mid_ratio.cnt_lt1
  mid_ratio.avg_gt1 /= mid_ratio.cnt_gt1
  mid_ratio.pct_lt1 = round((100.0*mid_ratio.cnt_lt1)/mid_ratio.cnt,1)
  mid_ratio.pct_gt1 = round((100.0*mid_ratio.cnt_gt1)/mid_ratio.cnt,1)

  if not exit_ratio.cnt:     exit_ratio.cnt = -1
  if not exit_ratio.cnt_lt1: exit_ratio.cnt_lt1 = -1
  if not exit_ratio.cnt_gt1: exit_ratio.cnt_gt1 = -1

  exit_ratio.avg     /= exit_ratio.cnt
  exit_ratio.avg_lt1 /= exit_ratio.cnt_lt1
  exit_ratio.avg_gt1 /= exit_ratio.cnt_gt1
  exit_ratio.pct_lt1 = round((100.0*exit_ratio.cnt_lt1)/exit_ratio.cnt,1)
  exit_ratio.pct_gt1 = round((100.0*exit_ratio.cnt_gt1)/exit_ratio.cnt,1)

  if not guardexit_ratio.cnt:     guardexit_ratio.cnt = -1
  if not guardexit_ratio.cnt_lt1: guardexit_ratio.cnt_lt1 = -1
  if not guardexit_ratio.cnt_gt1: guardexit_ratio.cnt_gt1 = -1

  guardexit_ratio.avg     /= guardexit_ratio.cnt
  guardexit_ratio.avg_lt1 /= guardexit_ratio.cnt_lt1
  guardexit_ratio.avg_gt1 /= guardexit_ratio.cnt_gt1
  guardexit_ratio.pct_lt1 = \
       round((100.0*guardexit_ratio.cnt_lt1)/guardexit_ratio.cnt,1)
  guardexit_ratio.pct_gt1 = \
       round((100.0*guardexit_ratio.cnt_gt1)/guardexit_ratio.cnt,1)

  #  Print ratios of All, Guard, Mid, Exit and Guard+Exit nodes
  #    - Print Num < 1, Num >= 1, avg < 1, avg >= 1, and avg for each
  print "Overall Cnt: "       +str(all_ratio.cnt)
  print "Overall Avg Ratio: "     +str(all_ratio.avg)
  print "Overall Ratios < 1 Pct: "+str(all_ratio.pct_lt1)
  print "Overall Ratios < 1 Avg: "+str(all_ratio.avg_lt1)
  print "Overall Ratios > 1 Pct: "+str(all_ratio.pct_gt1)
  print "Overall Ratios > 1 Avg: "+str(all_ratio.avg_gt1)
  print ""
  print "Guard Cnt: "       +str(guard_ratio.cnt)
  print "Guard Avg Ratio: "     +str(guard_ratio.avg)
  print "Guard Ratios < 1 Pct: "+str(guard_ratio.pct_lt1)
  print "Guard Ratios < 1 Avg: "+str(guard_ratio.avg_lt1)
  print "Guard Ratios > 1 Pct: "+str(guard_ratio.pct_gt1)
  print "Guard Ratios > 1 Avg: "+str(guard_ratio.avg_gt1)
  print ""
  print "Mid Cnt: "       +str(mid_ratio.cnt)
  print "Mid Avg Ratio: "     +str(mid_ratio.avg)
  print "Mid Ratios < 1 Pct: "+str(mid_ratio.pct_lt1)
  print "Mid Ratios < 1 Avg: "+str(mid_ratio.avg_lt1)
  print "Mid Ratios > 1 Pct: "+str(mid_ratio.pct_gt1)
  print "Mid Ratios > 1 Avg: "+str(mid_ratio.avg_gt1)
  print ""
  print "Exit Cnt: "       +str(exit_ratio.cnt)
  print "Exit Avg Ratio: "     +str(exit_ratio.avg)
  print "Exit Ratios < 1 Pct: "+str(exit_ratio.pct_lt1)
  print "Exit Ratios < 1 Avg: "+str(exit_ratio.avg_lt1)
  print "Exit Ratios > 1 Pct: "+str(exit_ratio.pct_gt1)
  print "Exit Ratios > 1 Avg: "+str(exit_ratio.avg_gt1)
  print ""
  print "Guard+Exit Cnt: "       +str(guardexit_ratio.cnt)
  print "Guard+Exit Avg Ratio: "     +str(guardexit_ratio.avg)
  print "Guard+Exit Ratios < 1 Pct: "+str(guardexit_ratio.pct_lt1)
  print "Guard+Exit Ratios < 1 Avg: "+str(guardexit_ratio.avg_lt1)
  print "Guard+Exit Ratios > 1 Pct: "+str(guardexit_ratio.pct_gt1)
  print "Guard+Exit Ratios > 1 Avg: "+str(guardexit_ratio.avg_gt1)
  print ""


for i in xrange(0,100,10):
  check(i,i+10)

check_entropy(sorted_rlist, 1500000)

check_ratios(sorted_rlist)
