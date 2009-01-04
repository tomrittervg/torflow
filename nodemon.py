#!/usr/bin/python
# Nodemon - Tor node monitor

"""
Nodemon - Tor node monitor
"""

from TorCtl import *
import sys
import socket
import traceback
import re
from TorCtl.TorUtil import control_port, control_host
from TorCtl.TorUtil import *
import sched, time
import thread

class Reason:
  def __init__(self, reason): self.reason = reason
  ncircs = 0
  count = 0

class RouterStats(TorCtl.Router):
  # Behold, a "Promotion Constructor"!
  # Also allows null superclasses! Python is awesome
  def __init__(self, r=None):
    if r:
      self.__dict__ = r.__dict__
    else:
      self.down = 0
    self.reasons = {} # For a fun time, move this outside __init__
  tot_ncircs = 0
  tot_count = 0
  tot_read = 0
  tot_wrote = 0
  running_read = 0
  running_wrote = 0
  tot_age = 0

errors = {}
errors_lock = thread.allocate_lock()
key_to_name = {}
name_to_key = {}

# TODO: Move these to config file
max_detach = 3

def read_routers(c, nslist):
  bad_key = 0
  errors_lock.acquire()
  for ns in nslist:
    try:
      key_to_name[ns.idhex] = ns.nickname
      name_to_key[ns.nickname] = ns.idhex
      r = RouterStats(c.get_router(ns))
      if ns.nickname in errors:
        if errors[ns.nickname].idhex != r.idhex:
          plog("NOTICE", "Router "+r.nickname+" has multiple keys: "
             +errors[ns.nickname].idhex+" and "+r.idhex)
      errors[r.nickname] = r # XXX: We get names only from ORCONN :(
    except TorCtl.ErrorReply:
      bad_key += 1
      if "Running" in ns.flags:
        plog("INFO", "Running router "+ns.nickname+"="
           +ns.idhex+" has no descriptor")
      pass
    except:
      traceback.print_exception(*sys.exc_info())
      continue
  errors_lock.release()

 
# Make eventhandler
class NodeHandler(TorCtl.EventHandler):
  def __init__(self, c):
    TorCtl.EventHandler.__init__(self)
    self.c = c

  def or_conn_status_event(self, o):
    # XXX: Count all routers as one?
    if re.search(r"^\$", o.endpoint):
      if o.endpoint not in key_to_name:
        o.endpoint = "AllClients:HASH"
      else: o.endpoint = key_to_name[o.endpoint]
    elif o.endpoint not in name_to_key:
      plog("DEBUG", "IP? " + o.endpoint)
      o.endpoint = "AllClients:IP"

    if o.status == "READ" or o.status == "WRITE":
      #plog("DEBUG", "Read: " + str(read) + " wrote: " + str(wrote))
      errors_lock.acquire()
      if o.endpoint not in errors:
        plog("NOTICE", "Buh?? No "+o.endpoint)
        errors[o.endpoint] = RouterStats()
        errors[o.endpoint].nickname = o.endpoint
      errors[o.endpoint].running_read += o.read_bytes
      errors[o.endpoint].running_wrote += o.wrote_bytes
      errors_lock.release()

      
    if o.status == "CLOSED" or o.status == "FAILED":
      errors_lock.acquire()
      if o.endpoint not in errors:
        plog("NOTICE", "Buh?? No "+o.endpoint)
        errors[o.endpoint] = RouterStats()
        errors[o.endpoint].nickname = o.endpoint
      if o.status == "FAILED" and not errors[o.endpoint].down:
        o.status = o.status + "(Running)"
      o.reason = o.status+":"+o.reason
      if o.reason not in errors[o.endpoint].reasons:
        errors[o.endpoint].reasons[o.reason] = Reason(o.reason)
      errors[o.endpoint].reasons[o.reason].ncircs += o.ncircs
      errors[o.endpoint].reasons[o.reason].count += 1
      errors[o.endpoint].tot_ncircs += o.ncircs
      errors[o.endpoint].tot_count += 1
      if o.age: errors[o.endpoint].tot_age += o.age
      if o.read_bytes: errors[o.endpoint].tot_read += o.read_bytes
      if o.wrote_bytes: errors[o.endpoint].tot_wrote += o.wrote_bytes
      errors_lock.release()
    else: return

    if o.age: age = "AGE="+str(o.age)
    else: age = ""
    if o.read_bytes: read = "READ="+str(o.read_bytes)
    else: read = ""
    if o.wrote_bytes: wrote = "WRITTEN="+str(o.wrote_bytes)
    else: wrote = ""
    if o.reason: reason = "REASON="+o.reason
    else: reason = ""
    if o.ncircs: ncircs = "NCIRCS="+str(o.ncircs)
    else: ncircs = ""
    plog("DEBUG",
        " ".join((o.event_name, o.endpoint, o.status, age, read, wrote,
               reason, ncircs)))

  def ns_event(self, n):
    read_routers(self.c, n.nslist)
 
  def new_desc_event(self, d):
    for i in d.idlist: # Is this too slow?
      read_routers(self.c, self.c.get_network_status("id/"+i))

def bw_stats(key, f):
  routers = errors.values()
  routers.sort(lambda x,y: cmp(key(y), key(x))) # Python < 2.4 hack

  for r in routers:
    f.write(r.nickname+"="+str(key(r))+"\n")
  
  f.close()
  
    
def save_stats(s):
  errors_lock.acquire()
  # Yes yes, adding + 0.005 to age is bloody.. but who cares,
  #  1. Routers sorted by bytes read
  bw_stats(lambda x: x.tot_read, file("./data/nodemon/r_by_rbytes", "w"))
  #  2. Routers sorted by bytes written
  bw_stats(lambda x: x.tot_wrote, file("./data/nodemon/r_by_wbytes", "w"))
  #  3. Routers sorted by tot bytes
  bw_stats(lambda x: x.tot_read+x.tot_wrote,
     file("./data/nodemon/r_by_tbytes", "w"))
  #  4. Routers sorted by downstream bw
  bw_stats(lambda x: x.tot_read/(x.tot_age+0.005),
     file("./data/nodemon/r_by_rbw", "w"))
  #  5. Routers sorted by upstream bw
  bw_stats(lambda x: x.tot_wrote/(x.tot_age+0.005),
      file("./data/nodemon/r_by_wbw", "w"))
  #  6. Routers sorted by total bw
  bw_stats(lambda x: (x.tot_read+x.tot_wrote)/(x.tot_age+0.005),
      file("./data/nodemon/r_by_tbw", "w"))

  bw_stats(lambda x: x.running_read,
      file("./data/nodemon/r_by_rrunbytes", "w"))
  bw_stats(lambda x: x.running_wrote,
      file("./data/nodemon/r_by_wrunbytes", "w"))
  bw_stats(lambda x: x.running_read+x.running_wrote,
      file("./data/nodemon/r_by_trunbytes", "w"))
  
  
  f = file("./data/nodemon/reasons", "w")
  routers = errors.values()
  def notlambda(x, y):
    if y.tot_ncircs or x.tot_ncircs:
      return cmp(y.tot_ncircs, x.tot_ncircs)
    else:
      return cmp(y.tot_count, x.tot_count)
  routers.sort(notlambda)

  for r in routers:
    f.write(r.nickname+" " +str(r.tot_ncircs)+"/"+str(r.tot_count)+"\n")
    for reason in r.reasons.itervalues():
      f.write("\t"+reason.reason+" "+str(reason.ncircs)+
           "/"+str(reason.count)+"\n")

  errors_lock.release()
  f.close()
  s.enter(60, 1, save_stats, (s,))


def startmon(c):
  global key_to_name, name_to_key
  nslist = c.get_network_status()
  read_routers(c, nslist)
  
  s=sched.scheduler(time.time, time.sleep)

  s.enter(60, 1, save_stats, (s,))
  s.run();


def main(argv):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((control_host,control_port))
  c = TorCtl.Connection(s)
  c.set_event_handler(NodeHandler(c))
  c.launch_thread()
  c.authenticate()
  c.set_events([TorCtl.EVENT_TYPE.ORCONN,
          TorCtl.EVENT_TYPE.NS,
          TorCtl.EVENT_TYPE.NEWDESC], True)
  startmon(c)


if __name__ == '__main__':
  main(sys.argv)
