#!/usr/bin/env python
# uses metatroller to collect circuit build times for 5% slices of guard nodes
# [OUTPUT] one directory, with three files: StatsHandler aggregate stats file, file with all circuit events (for detailed reference), file with just buildtimes

try:
  import psyco
  psyco.full()
except ImportError:
  #print 'Psyco not installed, the program will just run slower'
  pass

#import profile

import socket,sys,time,getopt,os,threading,atexit
sys.path.append("../../")
import TorCtl
from TorCtl.TorUtil import meta_port,meta_host,control_port,control_host,control_pass
from TorCtl.StatsSupport import StatsHandler
from TorCtl import PathSupport, TorCtl
from TorCtl.PathSupport import ExitPolicyRestriction,OrNodeRestriction
from TorCtl.TorUtil import plog

# Note: It is not recommended to set order_exits to True, because
# of the lifetime differences between this __selmgr and the 
# StatsGatherer when slicing the network into segments.
__selmgr = PathSupport.SelectionManager(
      pathlen=3,
      order_exits=False, 
      percent_fast=80,
      percent_skip=0,
      min_bw=1024,
      use_all_exits=False,
      uniform=True,
      use_exit=None,
      use_guards=True,
      restrict_guards=False)

# Maximum number of concurrent circuits to build:
# (Gets divided by the number of slices)
max_circuits = 60

# Original value of FetchUselessDescriptors
FUDValue = None

class StatsGatherer(StatsHandler):
  def __init__(self,c, selmgr,basefile_name,nstats):
    StatsHandler.__init__(self,c, selmgr)
    self.nodesfile = open(basefile_name + '.nodes','w')
    self.extendtimesfile = open(basefile_name + '.extendtimes','w')
    self.buildtimesfile = open(basefile_name + '.buildtimes','w')
    self.circ_built = 0
    self.nstats = nstats
    self.done = False
    # Set up the exit restriction to include either 443 or 80 exits.
    # Since Tor dynamically pre-builds circuits depending on port usage, and 
    # these are the two most commonly used user ports, this seems as good 
    # first approximation to model the dynamic behavior of a real client's 
    # circuit choice. 
    self.selmgr.exit_rstr.del_restriction(ExitPolicyRestriction)
    self.selmgr.exit_rstr.del_restriction(OrNodeRestriction)
    self.selmgr.exit_rstr.add_restriction(OrNodeRestriction([
                  ExitPolicyRestriction("255.255.255.255", 80), 
                  ExitPolicyRestriction("255.255.255.255", 443)]))


  def circ_status_event(self, circ_event):
    """ handles circuit status event """
    if circ_event.circ_id in self.circuits:
      if circ_event.status == 'EXTENDED':
        extend_time = circ_event.arrived_at-self.circuits[circ_event.circ_id].last_extended_at
        self.circuits[circ_event.circ_id].extend_times.append(extend_time)
        self.circuits[circ_event.circ_id].last_extended_at = circ_event.arrived_at

      if circ_event.status == 'BUILT':
        circ = self.circuits[circ_event.circ_id]
        buildtime = reduce(lambda x,y:x+y,circ.extend_times,0.0)
        self.extendtimesfile.write(str(circ.circ_id)+'\t'+'\t'.join(map(str, circ.extend_times))+'\n')
        self.extendtimesfile.flush()
        self.nodesfile.write(str(circ.circ_id)+'\t'+'\t'.join(self.circuits[circ_event.circ_id].id_path())+'\n')
        self.nodesfile.flush()
        self.buildtimesfile.write(str(circ.circ_id) + '\t' + str(buildtime) + '\n')
        self.buildtimesfile.flush()

      # check to see if done gathering data
      if circ_event.status == 'BUILT': 
        self.circ_built += 1
        self.close_circuit(circ_event.circ_id)
    StatsHandler.circ_status_event(self,circ_event)

def cleanup():
  s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect((control_host,control_port))
  c = PathSupport.Connection(s)
  c.authenticate(control_pass)  # also launches thread...
  global FUDValue
  from TorCtl.TorUtil import plog
  plog("INFO", "Resetting FetchUselessDescriptors="+FUDValue)
  c.set_option("FetchUselessDescriptors", FUDValue) 

def open_controller(filename,ncircuits):
  """ starts stat gathering thread """

  s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect((control_host,control_port))
  c = PathSupport.Connection(s)
  c.authenticate(control_pass)  # also launches thread...
  c.debug(file(filename+".log", "w"))
  h = StatsGatherer(c,__selmgr,filename,ncircuits)
  c.set_event_handler(h)
  global FUDValue
  if not FUDValue:
    FUDValue = c.get_option("FetchUselessDescriptors")[0][1]
  c.set_option("FetchUselessDescriptors", "1") 

  c.set_events([TorCtl.EVENT_TYPE.STREAM,
                TorCtl.EVENT_TYPE.BW,
                TorCtl.EVENT_TYPE.NS,
                TorCtl.EVENT_TYPE.CIRC,
                TorCtl.EVENT_TYPE.STREAM_BW,
                TorCtl.EVENT_TYPE.NEWDESC], True)
  return c

def getargs():
  ncircuits = ""
  dirname = ""
  filename = ""
  if len(sys.argv[1:]) < 3:
    usage()
    sys.exit(2)
  try:
    opts,args = getopt.getopt(sys.argv[1:],"b:e:s:n:d:g")
  except getopt.GetoptError,err:
    print str(err)
    usage()
  ncircuits=None
  begin=0
  end=80
  slice=5
  dirname=""
  guard_slices = False
  for o,a in opts:
    if o == '-n': 
      if a.isdigit(): ncircuits = int(a)
      else: usage()
    elif o == '-d': dirname = a  #directory where output files go 
    elif o == '-b':
      if a.isdigit(): begin = int(a)
      else: usage()
    elif o == '-e':
      if a.isdigit(): end = int(a)
      else: usage()
    elif o == '-s':
      if a.isdigit(): slice = int(a)
      else: usage()
    elif o == '-g':
      guard_slices = True
    else:
      assert False, "Bad option"
  return guard_slices,ncircuits,begin,end,slice,dirname

def usage():
    print 'usage: statscontroller.py [-b <#begin percentile>] [-e <end percentile] [-s <percentile slice size>] [-g] -n <# circuits> -d <output dir name>'
    sys.exit(1)

def guardslice(guard_slices,p,s,end,ncircuits,dirname):

  print 'Making new directory:',dirname
  if not os.path.isdir(dirname):
    os.mkdir(dirname)
  else:
    print 'Directory',dirname,'exists, not making a new one.'

  print 'Guard percentiles:',p,'to',s
  print '#Circuits',ncircuits

  basefile_name = dirname + '/' + str(p) + '-' + str(s) + '.' + str(ncircuits)
  aggfile_name =  basefile_name + '.agg'

  # Ok, since we create a new StatsGatherer each segment..
  __selmgr.percent_fast = s
  __selmgr.percent_skip = p
  __selmgr.restrict_guards_only = guard_slices

  if s-p >= end or guard_slices:
    print 'Using bandwidth weighted selection'
    __selmgr.uniform = False 
    __selmgr.use_guards = True
  else: 
    print 'Using uniform weighted selection'
    __selmgr.uniform = True
    __selmgr.use_guards = False

  # Need to kill the old ordered exit generator because it has
  # an old sorted router list.
  __selmgr.__ordered_exit_gen = None

  c = open_controller(basefile_name,ncircuits)

 
  for i in xrange(0,ncircuits):
    print 'Building circuit',i
    try:
      def circuit_builder(h):
        # reschedule if some number n circuits outstanding
        if h.circ_count - h.circ_succeeded - h.circ_failed > max_circuits:
          from TorCtl.TorUtil import plog
          plog("DEBUG", "Too many circuits: "+str(h.circ_count-h.circ_succeeded-h.circ_failed)+", delaying build")
          h.schedule_low_prio(circuit_builder)
          return
        circ = h.c.build_circuit(h.selmgr.pathlen, h.selmgr.path_selector)   
        h.circuits[circ.circ_id] = circ
      c._handler.schedule_low_prio(circuit_builder)
    except TorCtl.ErrorReply,e:
      plog("NOTICE","Error building circuit: " + str(e.args))

  while True:
    time.sleep(1)
    if c._handler.circ_built + c._handler.circ_failed >= ncircuits:
      print 'Done gathering stats for slice',p,'to',s,'on',ncircuits
      print c._handler.circ_built,'built',c._handler.circ_failed,'failed' 
      break

  cond = threading.Condition() 
  def notlambda(h):
    cond.acquire()
    h.close_all_circuits()
    h.write_stats(aggfile_name)
    cond.notify()
    cond.release()
    print "Wrote stats."
  cond.acquire()
  c._handler.schedule_low_prio(notlambda)
  cond.wait()
  cond.release()
  c.close()
  c._thread.join()
  print "Done in main."

def main():
  guard_slices,ncircuits,begin,end,pct,dirname = getargs()
 
  atexit.register(cleanup) 
  #global max_circuits
  #max_circuits = max_circuits/((end-begin)/pct)

  print "Using max_circuits: "+str(max_circuits)

  for p in xrange(begin,end,pct):
    guardslice(guard_slices,p,p+pct,end,ncircuits,dirname)

if __name__ == '__main__':
  main()
  #profile.run("main()", "prof.out")
