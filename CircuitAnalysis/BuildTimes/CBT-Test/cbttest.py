#!/usr/bin/python

try:
  import psyco
  psyco.full()
except ImportError:
  #print 'Psyco not installed, the program will just run slower'
  pass

#import profile

import socket,sys,time,getopt,os,threading,atexit
sys.path.append("../../../")
sys.path.append("../")
import shutil
from TorCtl import TorUtil
import TorCtl
from TorCtl.TorCtl import EventHandler, PreEventListener
from TorCtl import PathSupport, TorCtl
from TorCtl.PathSupport import ExitPolicyRestriction,OrNodeRestriction,RestrictionError
from TorCtl.TorUtil import plog
import traceback

# XXX: Add to config
MAX_CIRCUITS = 10
PCT_SKIP     = 10
# XXX: Are these two the right way to go?
# Should we maybe have MIN_STREAK and MIN_FUZZY too?
STREAK_RATIO = 0.5
FUZZY_RATIO  = 0.5
MIN_STREAK = 50
MIN_FUZZY = 50

# CLI Options variables.
# Yes, a hack.
full_run = False
output_dir = None
pct_start = None

# Original value of FetchUselessDescriptors
FUDValue = None

class CircTime:
  def __init__(self, start_time):
    self.start_time = start_time
    self.end_time = 0

class CircHandler(EventHandler):
  def __init__(self, c, guards):
    EventHandler.__init__(self)
    self.c = c
    self.circs = {}
    self.live_circs = {}
    self.timeout_circs = {}
    self.closed_circs = {}
    self.built_circs = {}
    self.circ_times = {}
    self.up_guards = {}
    for g in guards:
      self.up_guards[g.idhex] = g
    self.down_guards = {}
    self.buildtimes_file = file(output_dir+"/buildtimes", "w")

  def heartbeat_event(self, event):
    if len(self.live_circs) < MAX_CIRCUITS:
       circ_id = self.c.extend_circuit()
       plog("INFO", "Launched circuit: "+str(circ_id))

  def guard_event(self, event):
    changed = False
    plog("NOTICE", "Guard $"+event.idhex+" is "+event.status)
    # XXX: remove from our list of guards and get a new one
    if event.status == "DOWN":
      if event.idhex in self.up_guards:
        self.down_guards[event.idhex] = self.up_guards[event.idhex]
        del self.up_guards[event.idhex]
      # If more than 2 are down, add one
      if len(self.up_guards) < 2:
        changed = True
        guards = get_guards(2-len(self.up_guards))
        for g in guards:
          plog("NOTICE", "Adding guard $"+g.idhex)
          self.up_guards[g.idhex] = g
    elif event.status == "DROPPED":
      if event.idhex in self.up_guards:
        del self.up_guards[event.idhex]
      if event.idhex in self.down_guards:
        del self.down_guards[event.idhex]
      guards = get_guards(1)
      changed = True
      for g in guards:
        plog("NOTICE", "Adding guard $"+g.idhex)
        self.up_guards[g.idhex] = g
    elif event.status == "UP":
      plog("NOTICE", "Adding guard $"+g.idhex)
      if event.idhex in self.down_guards:
        self.up_guards[event.idhex] = self.down_guards[event.idhex]
        del self.down_guards[event.idhex]
    if changed:
      guard_str = ",".join(map(lambda r: "$"+r.idhex, self.up_guards.values()))
      if self.down_guards:
        guard_str += ","+",".join(map(lambda r:
                      "$"+r.idhex, self.down_guards.values()))
      plog("NOTICE", "Setting guards: "+guard_str)
      self.c.setcont("EntryNodes", guard_str)

  def close_all_circs(self):
    lines = self.c.sendAndRecv("GETINFO circuit-status\r\n")[0][2]
    if lines: lines = lines.split("\n")
    else: return
    for l in lines:
      if l:
        line_parts = l.split(" ")
        plog("INFO", "Closing aleady built circuit "+str(line_parts[0]))
        self.live_circs[int(line_parts[0])] = True
        self.circs[int(line_parts[0])] = True
        self.c.close_circuit(int(line_parts[0]))

  # XXX: Log built and timeout circs to buildtimes_file for post-analysis
  def circ_status_event(self, circ_event):
    if circ_event.status == 'LAUNCHED':
      self.circs[circ_event.circ_id] = circ_event.status
      self.circ_times[circ_event.circ_id] = CircTime(circ_event.arrived_at)
      self.live_circs[circ_event.circ_id] = True
    elif circ_event.status == 'BUILT':
      self.circs[circ_event.circ_id] = circ_event.status
      self.built_circs[circ_event.circ_id] = True
      self.c.close_circuit(circ_event.circ_id)
      if circ_event.circ_id in self.circ_times:
        self.circ_times[circ_event.circ_id].end_time = circ_event.arrived_at
        plog("INFO", "Closing circuit "+str(circ_event.circ_id)+" with build time of "+str(self.circ_times[circ_event.circ_id].end_time-self.circ_times[circ_event.circ_id].start_time))
    elif circ_event.status == 'FAILED' or circ_event.status == 'CLOSED':
      self.circs[circ_event.circ_id] = circ_event.status
      if circ_event.circ_id in self.live_circs:
        del self.live_circs[circ_event.circ_id]
      if circ_event.reason == 'TIMEOUT':
        self.timeout_circs[circ_event.circ_id] = True
        if circ_event.circ_id in self.circ_times:
          self.circ_times[circ_event.circ_id].end_time = circ_event.arrived_at
          plog("INFO", circ_event.status+" timeout circuit "+str(circ_event.circ_id)+" with build time of "+str(self.circ_times[circ_event.circ_id].end_time-self.circ_times[circ_event.circ_id].start_time))
      else:
        self.closed_circs[circ_event.circ_id] = True

class BuildTimeoutTracker(PreEventListener):
  def __init__(self, cond):
    PreEventListener.__init__(self)
    self.cond = cond
    self.reset()
    self.reset_total = 0

  def reset(self):
    self.last_timeout = 0
    self.timeout_streak = 0
    self.timeout_fuzzy_streak = 0
    self.buildtimeout_fuzzy = None
    self.buildtimeout_strict = None
    self.fuzzy_streak_count = 0
    self.strict_streak_count = 0
    self.total_times = 0

  def buildtimeout_set_event(self, bt_event):
    plog("INFO", "Got buildtimeout event: "+bt_event.set_type+" TOTAL_TIMES="
                 +str(bt_event.total_times)+" TIMEOUT_MS="
                 +str(bt_event.timeout_ms))

    # Need to handle RESET events..
    # XXX: Should these count towards our totals, or should we just start
    # over? Probably, but then that breaks a lot of our asserts
    # below...
    if bt_event.set_type == "RESET":
      plog("NOTICE", "Got RESET event. Resetting counts")
      self.reset_total += self.total_times
      self.reset()
      return

    if not self.total_times:
      self.total_times = bt_event.total_times-1
    self.total_times +=1
    # Ensure we don't wrap during testing:
    assert(self.total_times == bt_event.total_times)

    if not self.buildtimeout_strict:
      self.buildtimeout_strict = bt_event
    if not self.buildtimeout_fuzzy:
      self.buildtimeout_fuzzy = bt_event

    fuzzy_last = int(round(self.buildtimeout_fuzzy.timeout_ms, -3))
    fuzzy_curr = int(round(bt_event.timeout_ms, -3))
    fuzzy_diff = abs(fuzzy_last-fuzzy_curr)
    if fuzzy_diff > 1000:
      self.buildtimeout_fuzzy = None
      self.fuzzy_streak_count = 0
      self.cond.min_circs = 0
      try: os.unlink(output_dir+"/state.min")
      except: pass
    elif not self.cond.min_circs:
      assert(self.fuzzy_streak_count ==
              (bt_event.total_times - self.buildtimeout_fuzzy.total_times))
      self.fuzzy_streak_count += 1
      if (self.fuzzy_streak_count >= self.total_times*FUZZY_RATIO):
        plog("NOTICE",
             "Fuzzy termination condition reached at "
             +str(self.total_times-self.fuzzy_streak_count)
             +" with streak of "+str(self.fuzzy_streak_count)
             +" and reset count of "+str(self.reset_total))
        self.cond.min_circs = self.reset_total+self.total_times \
                                - self.fuzzy_streak_count
        shutil.copyfile('./tor-data/state', output_dir+"/state.min")

    strict_last = int(round(self.buildtimeout_strict.timeout_ms, -3))
    strict_curr = int(round(bt_event.timeout_ms, -3))
    strict_diff = abs(strict_last-strict_curr)
    if strict_diff > 0:
      self.buildtimeout_strict = None
      self.strict_streak_count = 0
    else:
      if (self.strict_streak_count != (bt_event.total_times -
                 self.buildtimeout_strict.total_times)):
        plog("WARN",
             "Streak count doesn't match: "+str(self.strict_streak_count)+
             " != "+str(bt_event.total_times)
                     +"-"+str(self.buildtimeout_strict.total_times))
        assert(self.strict_streak_count ==
              (bt_event.total_times - self.buildtimeout_strict.total_times))
      self.strict_streak_count += 1
      if (self.cond.min_circs and self.strict_streak_count >= self.total_times*STREAK_RATIO):
        plog("NOTICE",
             "Strict termination condition reached at "
             +str(self.total_times-self.strict_streak_count)
             +" with streak of "+str(self.strict_streak_count)
             +" and reset count of "+str(self.reset_total))
        shutil.copyfile('./tor-data/state', output_dir+"/state.full")
        self.cond.acquire()
        self.cond.num_circs = self.reset_total+self.total_times-\
                                  self.strict_streak_count
        self.cond.notify()
        self.cond.release()

def get_guards(c, n):
  # Get list of live routers
  sorted_rlist = filter(lambda r: not r.down,
                    c.read_routers(c.get_network_status()))
  sorted_rlist.sort(lambda x, y: cmp(y.bw, x.bw))
  for i in xrange(len(sorted_rlist)): sorted_rlist[i].list_rank = i

  guard_rst = PathSupport.FlagsRestriction(["Guard"], [])
  pct_rst = PathSupport.PercentileRestriction(pct_start, pct_start+PCT_SKIP, sorted_rlist)

  guard_gen = PathSupport.UniformGenerator(sorted_rlist,
                PathSupport.NodeRestrictionList([guard_rst, pct_rst]))
  guard_gen.rewind()

  ggen = guard_gen.generate()

  # Generate 3 guards
  guards = []
  for i in xrange(n):
    guards.append(ggen.next())

  return guards

def cleanup():
  s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect((TorUtil.control_host,TorUtil.control_port))
  c = PathSupport.Connection(s)
  c.authenticate_cookie(file("./tor-data/control_auth_cookie", "r"))
  global FUDValue
  from TorCtl.TorUtil import plog
  plog("INFO", "Resetting FetchUselessDescriptors="+FUDValue)
  c.set_option("FetchUselessDescriptors", FUDValue)

def open_controller(filename):
  """ starts stat gathering thread """

  s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect((TorUtil.control_host,TorUtil.control_port))
  c = TorCtl.Connection(s)
  t = c.launch_thread()
  c.authenticate_cookie(file("./tor-data/control_auth_cookie", "r"))
  c.debug(file(filename+".log", "w", buffering=0))

  guards = get_guards(c, 3)
  guard_str = ",".join(map(lambda r: "$"+r.idhex, guards))

  plog("NOTICE", "Choosing guards: "+guard_str)
  # Setconf guards for percentile range
  c.set_option("EntryNodes", guard_str)
  c.set_option("StrictNodes", "1")

  cond = threading.Condition()
  cond.min_circs = 0 # Python haxx
  cond.num_circs = 0 # Python haxx
  cond.acquire()

  h = CircHandler(c, guards)
  c.set_event_handler(h)
  c.add_event_listener(BuildTimeoutTracker(cond))

  global FUDValue
  if not FUDValue:
    FUDValue = c.get_option("FetchUselessDescriptors")[0][1]
  c.set_option("FetchUselessDescriptors", "1")

  c.set_events([TorCtl.EVENT_TYPE.BUILDTIMEOUT_SET,
                TorCtl.EVENT_TYPE.BW,
                TorCtl.EVENT_TYPE.GUARD,
                TorCtl.EVENT_TYPE.CIRC], True)

  # Close all the already open circuits to start fresh
  h.close_all_circs()
  cond.wait()
  cond.release()

  # Write to output_file:
  # 1. Num circs
  # 2. Guards used
  # 3. Failure quantile (in rerun only)
  out = file(output_dir+"/result", "a")
  out.write("NUM_CIRCS: "+str(cond.min_circs))
  out.write("MIN_CIRCS: "+str(cond.num_circs))

  return 0

def getargs():
  if len(sys.argv[1:]) < 3:
    usage()
    sys.exit(2)
  try:
    opts,args = getopt.getopt(sys.argv[1:],"p:o:b:fmr")
  except getopt.GetoptError,err:
    print str(err)
    usage()

  global pct_start
  global output_dir

  for o,a in opts:
    if o == '-p':
      pct_start = int(a)
    elif o == '-o':
      output_dir = a
    # XXX: -r retest
    else:
      assert False, "Bad option"

  return (output_dir, pct_start)

def usage():
    print 'usage: FOAD'
    sys.exit(1)

def main():
  #guard_slices,ncircuits,max_circuits,begin,end,pct,dirname,use_sql = getargs()
  TorUtil.read_config('cbt.cfg')

  try:
    getargs()
    atexit.register(cleanup)
    return open_controller("cbtest")
  except PathSupport.NoNodesRemain:
    print 'No nodes remain at this percentile range.'
    return 1
  except Exception, e:
    plog("ERROR", "Misc exception: "+str(e))
    traceback.print_exc()
    return 23

  #print "Using max_circuits: "+str(TorUtil.max_circuits)

if __name__ == '__main__':
  sys.exit(main())
  #profile.run("main()", "prof.out")
