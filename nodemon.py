#!/usr/bin/python
# Nodemon - Tor node monitor

"""
Nodemon - Tor node monitor
"""

import TorCtl
import atexit
import sys
import socket
import struct
import traceback
import re
import random
from TorUtil import *
import sched, time
import thread
import copy

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

# XXX: Move these to config file
control_host = "127.0.0.1"
control_port = 9051
max_detach = 3

def read_routers(c, nslist):
    bad_key = 0
    errors_lock.acquire()
    for ns in nslist:
        try:
            key_to_name[ns.idhex] = ns.name
            name_to_key[ns.name] = ns.idhex
            r = RouterStats(c.get_router(ns))
            if ns.name in errors:
                if errors[ns.name].idhex != r.idhex:
                    plog("NOTICE", "Router "+r.name+" has multiple keys: "
                         +errors[ns.name].idhex+" and "+r.idhex)
            errors[r.name] = r # XXX: We get names only from ORCONN :(
        except TorCtl.ErrorReply:
            bad_key += 1
            if "Running" in ns.flags:
                plog("INFO", "Running router "+ns.name+"="
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

    def or_conn_status(self, eventtype, status, target, age, read, wrote,
                       reason, ncircs):
        # XXX: Count all routers as one?
        if re.search(r"^\$", target):
            if target not in key_to_name:
                target = "AllClients:HASH"
            else: target = key_to_name[target]
        elif target not in name_to_key:
            plog("DEBUG", "IP? " + target)
            target = "AllClients:IP"

        if status == "READ" or status == "WRITE":
            #plog("DEBUG", "Read: " + str(read) + " wrote: " + str(wrote))
            errors_lock.acquire()
            if target not in errors:
                plog("NOTICE", "Buh?? No "+target)
                errors[target] = RouterStats()
                errors[target].name = target
            errors[target].running_read += read
            errors[target].running_wrote += wrote
            errors_lock.release()

            
        if status == "CLOSED" or status == "FAILED":
            errors_lock.acquire()
            if target not in errors:
                plog("NOTICE", "Buh?? No "+target)
                errors[target] = RouterStats()
                errors[target].name = target
            if status == "FAILED" and not errors[target].down:
                status = status + "(Running)"
            reason = status+":"+reason
            if reason not in errors[target].reasons:
                errors[target].reasons[reason] = Reason(reason)
            errors[target].reasons[reason].ncircs += ncircs
            errors[target].reasons[reason].count += 1
            errors[target].tot_ncircs += ncircs
            errors[target].tot_count += 1
            if age: errors[target].tot_age += age
            if read: errors[target].tot_read += read
            if wrote: errors[target].tot_wrote += wrote
            errors_lock.release()
        else: return
        if age: age = "AGE="+str(age)
        else: age = ""
        if read: read = "READ="+str(read)
        else: read = ""
        if wrote: wrote = "WRITTEN="+str(wrote)
        else: wrote = ""
        if reason: reason = "REASON="+reason
        else: reason = ""
        if ncircs: ncircs = "NCIRCS="+str(ncircs)
        else: ncircs = ""
        plog("DEBUG",
                " ".join((eventtype, target, status, age, read, wrote,
                           reason, ncircs)))

    def ns(self, eventtype, nslist):
        read_routers(self.c, nslist)
 
    def new_desc(self, eventtype, identities):
        for i in identities: # Is this too slow?
            read_routers(self.c, self.c.get_network_status("id/"+i))

def bw_stats(key, f):
    routers = errors.values()
    routers.sort(lambda x,y: cmp(key(y), key(x))) # Python < 2.4 hack

    for r in routers:
        f.write(r.name+"="+str(key(r))+"\n")
    
    f.close()
    
        
def save_stats(s):
    errors_lock.acquire()
    # Yes yes, adding + 0.005 to age is bloody.. but who cares,
    #    1. Routers sorted by bytes read
    bw_stats(lambda x: x.tot_read, file("./data/r_by_rbytes", "w"))
    #    2. Routers sorted by bytes written
    bw_stats(lambda x: x.tot_wrote, file("./data/r_by_wbytes", "w"))
    #    3. Routers sorted by tot bytes
    bw_stats(lambda x: x.tot_read+x.tot_wrote, file("./data/r_by_tbytes", "w"))
    #    4. Routers sorted by downstream bw
    bw_stats(lambda x: x.tot_read/(x.tot_age+0.005),
             file("./data/r_by_rbw", "w"))
    #    5. Routers sorted by upstream bw
    bw_stats(lambda x: x.tot_wrote/(x.tot_age+0.005), file("./data/r_by_wbw", "w"))
    #    6. Routers sorted by total bw
    bw_stats(lambda x: (x.tot_read+x.tot_wrote)/(x.tot_age+0.005),
             file("./data/r_by_tbw", "w"))

    bw_stats(lambda x: x.running_read,
            file("./data/r_by_rrunbytes", "w"))
    bw_stats(lambda x: x.running_wrote,
            file("./data/r_by_wrunbytes", "w"))
    bw_stats(lambda x: x.running_read+x.running_wrote,
            file("./data/r_by_trunbytes", "w"))
    
    
    f = file("./data/reasons", "w")
    routers = errors.values()
    def notlambda(x, y):
        if y.tot_ncircs or x.tot_ncircs:
            return cmp(y.tot_ncircs, x.tot_ncircs)
        else:    
            return cmp(y.tot_count, x.tot_count)
    routers.sort(notlambda)

    for r in routers:
        f.write(r.name+" " +str(r.tot_ncircs)+"/"+str(r.tot_count)+"\n")
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
    c = TorCtl.get_connection(s)
    c.set_event_handler(NodeHandler(c))
    th = c.launch_thread()
    c.authenticate()
    c.set_events([TorCtl.EVENT_TYPE.ORCONN,
                  TorCtl.EVENT_TYPE.NS,
                  TorCtl.EVENT_TYPE.NEWDESC], True)
    startmon(c)

main(sys.argv)
