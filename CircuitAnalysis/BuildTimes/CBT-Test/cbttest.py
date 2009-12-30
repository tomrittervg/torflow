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
from TorCtl import TorUtil
import TorCtl
from TorCtl.TorCtl import EventHandler, PreEventListener
from TorCtl import PathSupport, TorCtl
from TorCtl.PathSupport import ExitPolicyRestriction,OrNodeRestriction,RestrictionError
from TorCtl.TorUtil import plog

# XXX: Add to config
MAX_CIRCUITS = 5
STREAK_RATIO = 0.5
FUZZY_RATIO = 0.5

# Original value of FetchUselessDescriptors
FUDValue = None

class CircTime:
  def __init__(self, start_time):
    self.start_time = start_time
    self.end_time = 0

class CircHandler(EventHandler):
  def __init__(self, c):
    EventHandler.__init__(self)
    self.c = c
    self.circs = {}
    self.live_circs = {}
    self.timeout_circs = {}
    self.closed_circs = {}
    self.circ_times = {}

  def heartbeat_event(self, event):
    if len(self.live_circs) < MAX_CIRCUITS:
       circ_id = self.c.extend_circuit()
       plog("INFO", "Launched circuit: "+str(circ_id))

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

  # XXX: Also time circs...
  def circ_status_event(self, circ_event):
    if circ_event.status == 'LAUNCHED':
      self.circs[circ_event.circ_id] = circ_event.status
      self.circ_times[circ_event.circ_id] = CircTime(circ_event.arrived_at)
      self.live_circs[circ_event.circ_id] = True
    elif circ_event.status == 'BUILT':
      self.circs[circ_event.circ_id] = circ_event.status
      self.c.close_circuit(circ_event.circ_id)
      if circ_event.circ_id in self.circ_times:
        self.circ_times[circ_event.circ_id].end_time = circ_event.arrived_at
        plog("INFO", "Closing circuit "+str(circ_event.circ_id)+" with build time of "+str(self.circ_times[circ_event.circ_id].end_time-self.circ_times[circ_event.circ_id].start_time))
    elif circ_event.status == 'FAILED' or circ_event.status == 'CLOSED':
      plog("INFO", circ_event.status+" circuit "+str(circ_event.circ_id))
      self.circs[circ_event.circ_id] = circ_event.status
      # XXX: Record this differently..
      #if circ_event.circ_id in self.circ_times:
      #  self.circ_times[circ_event.circ_id].end_time = circ_event.arrived_at
      del self.live_circs[circ_event.circ_id]
      if circ_event.reason == 'TIMEOUT':
        self.timeout_circs[circ_event.circ_id] = True
      else:
        self.closed_circs[circ_event.circ_id] = True

class BuildTimeoutTracker(PreEventListener):
  def __init__(self):
    PreEventListener.__init__(self)
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
    if not self.total_times:
      self.total_times = bt_event.total_times-1
    self.total_times +=1
    # Ensure we don't wrap during testing:
    assert(self.total_times == bt_event.total_times)

    if not self.buildtimeout_strict:
      self.buildtimeout_strict = bt_event
    if not self.buildtimeout_fuzzy:
      self.buildtimeout_fuzzy = bt_event

    strict_last = int(round(self.buildtimeout_strict.timeout_ms, -3))
    strict_curr = int(round(bt_event.timeout_ms, -3))
    strict_diff = abs(strict_last-strict_curr)
    if strict_diff > 0:
      self.buildtimeout_strict = bt_event
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
      if (self.strict_streak_count >= self.total_times*STREAK_RATIO):
        plog("NOTICE",
             "Strict termination condition reached at "
             +str(self.total_times-self.strict_streak_count)
             +" with streak of "+str(self.strict_streak_count))
        # XXX: Signal termination condition

    fuzzy_last = int(round(self.buildtimeout_fuzzy.timeout_ms, -3))
    fuzzy_curr = int(round(bt_event.timeout_ms, -3))
    fuzzy_diff = abs(fuzzy_last-fuzzy_curr)
    if fuzzy_diff > 1000:
      self.buildtimeout_fuzzy = bt_event
      self.fuzzy_streak_count = 0
    else:
      assert(self.fuzzy_streak_count ==
              (bt_event.total_times - self.buildtimeout_fuzzy.total_times))
      self.fuzzy_streak_count += 1
      if (self.strict_streak_count >= self.total_times*STREAK_RATIO):
        plog("NOTICE",
             "Strict termination condition reached at "
             +str(self.total_times-self.strict_streak_count)
             +" with streak of "+str(self.strict_streak_count))
        # XXX: Signal termination condition



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
  h = CircHandler(c)
  c.set_event_handler(h)
  c.add_event_listener(BuildTimeoutTracker())

  global FUDValue
  if not FUDValue:
    FUDValue = c.get_option("FetchUselessDescriptors")[0][1]
  c.set_option("FetchUselessDescriptors", "1")

  c.set_events([TorCtl.EVENT_TYPE.BUILDTIMEOUT_SET,
                TorCtl.EVENT_TYPE.BW,
                TorCtl.EVENT_TYPE.CIRC], True)

  # Close all the already open circuits to start fresh
  h.close_all_circs()
  return (c,t)

def getargs():
  if len(sys.argv[1:]) < 3:
    usage()
    sys.exit(2)
  try:
    opts,args = getopt.getopt(sys.argv[1:],"p:o:fmr")
  except getopt.GetoptError,err:
    print str(err)
    usage()
  for o,a in opts:
    if o == '-n': pass
    elif o == '-d': pass
    else:
      assert False, "Bad option"
  return 0

def usage():
    print 'usage: FOAD'
    sys.exit(1)

def main():
  #guard_slices,ncircuits,max_circuits,begin,end,pct,dirname,use_sql = getargs()
  TorUtil.read_config('cbt.cfg')

  try:
    # XXX: Setconf guards for percentile range
    atexit.register(cleanup)
    (c,t) = open_controller("cbtest")
    t.join()
  except PathSupport.NoNodesRemain:
    print 'No nodes remain at this percentile range.'
    return

  return (c,t)
  #print "Using max_circuits: "+str(TorUtil.max_circuits)

if __name__ == '__main__':
  main()
  #profile.run("main()", "prof.out")
