#!/usr/bin/python
# Metatroller. 

"""
Metatroller - Tor Meta controller
"""

import atexit
import sys
import socket
import traceback
import re
import random
import datetime
import threading
import struct
import copy
import time
from TorCtl import *
from TorCtl.TorUtil import *
from TorCtl.PathSupport import *

mt_version = "0.1.0-dev"

# TODO: Move these to config file
# TODO: Option to ignore guard flag
control_host = "127.0.0.1"
control_port = 9061
meta_host = "127.0.0.1"
meta_port = 9052
max_detach = 3

# Do NOT modify this object directly after it is handed to PathBuilder
# Use PathBuilder.schedule_reconfigure instead.
# (Modifying the arguments here is OK)
__selmgr = PathSupport.SelectionManager(
            pathlen=3,
            order_exits=False,
            percent_fast=100,
            percent_skip=0,
            min_bw=1024,
            use_all_exits=False,
            uniform=True,
            use_exit=None,
            use_guards=False)


# Technically we could just add member vars as we need them, but this
# is a bit more clear
class StatsRouter(TorCtl.Router):
    def __init__(self, router): # Promotion constructor :)
        self.__dict__ = router.__dict__
        self.reset()
    
    def reset(self):
        self.circ_uncounted = 0
        self.circ_failed = 0
        self.circ_succeeded = 0
        self.circ_suspected = 0
        self.circ_selections = 0 # above 4 should add to this
        self.strm_failed = 0 # Only exits should have these
        self.strm_succeeded = 0
        self.strm_suspected = 0
        self.strm_uncounted = 0
        self.strm_selections = 0 # above 3 should add to this
        self.reason_suspected = {}
        self.reason_failed = {}
        self.first_seen = time.time()
        if "Running" in self.flags:
            self.became_active_at = self.first_seen
            self.hibernated_at = 0
        else:
            self.became_active_at = 0
            self.hibernated_at = self.first_seen
        self.total_hibernation_time = 0
        self.total_active_uptime = 0
        self.max_bw = 0
        self.min_bw = 0
        self.avg_bw = 0
    
    def sanity_check(self):
        if self.circ_failed + self.circ_succeeded + self.circ_suspected \
            + self.circ_uncounted != self.circ_selections:
            plog("ERROR", self.nickname+" does not add up for circs")
        if self.strm_failed + self.strm_succeeded + self.strm_suspected \
            + self.strm_uncounted != self.strm_selections:
            plog("ERROR", self.nickname+" does not add up for streams")
        def check_reasons(reasons, expected, which, rtype):
            count = 0
            for rs in reasons.iterkeys():
                if re.search(r"^"+which, rs): count += reasons[rs]
            if count != expected:
                plog("ERROR", "Mismatch "+which+" "+rtype+" for "+self.nickname)
        check_reasons(self.reason_suspected,self.strm_suspected,"STREAM","susp")
        check_reasons(self.reason_suspected,self.circ_suspected,"CIRC","susp")
        check_reasons(self.reason_failed,self.strm_failed,"STREAM","failed")
        check_reasons(self.reason_failed,self.circ_failed,"CIRC","failed")
        now = time.time()
        tot_hib_time = self.total_hibernation_time
        tot_uptime = self.total_active_uptime
        if self.hibernated_at: tot_hib_time += now - self.hibernated_at
        if self.became_active_at: tot_uptime += now - self.became_active_at
        if round(tot_hib_time+tot_uptime) != round(now-self.first_seen):
            plog("ERROR", "Mismatch of uptimes for "+self.nickname)

class StatsHandler(PathSupport.PathBuilder):
    def __init__(self, c, slmgr):
        PathBuilder.__init__(self, c, slmgr, StatsRouter)

    def write_stats(self, filename):
        # FIXME: Sort this by different values.
        plog("DEBUG", "Writing stats")
        for r in self.sorted_r:
            r.sanity_check()

    def reset_stats(self):
        for r in self.sorted_r:
            r.reset()

    # TODO: Use stream bandwidth events to implement reputation system
    # from
    # http://www.cs.colorado.edu/department/publications/reports/docs/CU-CS-1025-07.pdf
    # (though my bet's on it not working on a real Tor network)

    def circ_status_event(self, c):
        if c.circ_id in self.circuits:
            # XXX: Hrmm, consider making this sane in TorCtl.
            if c.reason: lreason = c.reason
            else: lreason = "NONE"
            if c.remote_reason: rreason = c.remote_reason
            else: rreason = "NONE"
            reason = c.event_name+":"+c.status+":"+lreason+":"+rreason
            if c.status == "FAILED":
                # update selection count
                for r in self.circuits[c.circ_id].path: r.circ_selections += 1
                
                if len(c.path)-1 < 0: start_f = 0
                else: start_f = len(c.path)-1 

                # Count failed
                for r in self.circuits[c.circ_id].path[start_f:len(c.path)+1]:
                    r.circ_failed += 1
                    if not reason in r.reason_failed:
                        r.reason_failed[reason] = 1
                    else: r.reason_failed[reason]+=1

                for r in self.circuits[c.circ_id].path[len(c.path)+1:]:
                    r.circ_uncounted += 1

                # Don't count if failed was set this round, don't set 
                # suspected..
                for r in self.circuits[c.circ_id].path[:start_f]:
                    r.circ_suspected += 1
                    if not reason in r.reason_suspected:
                        r.reason_suspected[reason] = 1
                    else: r.reason_suspected[reason]+=1
            elif c.status == "CLOSED":
                # Since PathBuilder deletes the circuit on a failed, 
                # we only get this for a clean close
                # Update circ_selections count
                for r in self.circuits[c.circ_id].path:
                    r.circ_selections += 1
                
                    if lreason in ("REQUESTED", "FINISHED", "ORIGIN"):
                        r.circ_succeeded += 1
                    else:
                        if not reason in r.reason_suspected:
                            r.reason_suspected[reason] = 1
                        else: r.reason_suspected[reason] += 1
                        r.circ_suspected+= 1
        PathBuilder.circ_status_event(self, c)
    
    def stream_status_event(self, s):
        if s.strm_id in self.streams:
            # XXX: Hrmm, consider making this sane in TorCtl.
            if s.reason: lreason = s.reason
            else: lreason = "NONE"
            if s.remote_reason: rreason = s.remote_reason
            else: rreason = "NONE"
            reason = s.event_name+":"+s.status+":"+lreason+":"+rreason+":"+self.streams[s.strm_id].kind
            if s.status in ("DETACHED", "FAILED", "CLOSED", "SUCCEEDED") \
                    and not s.circ_id:
                plog("WARN", "Stream "+str(s.strm_id)+" detached from no circuit!")
                PathBuilder.stream_status_event(self, s)
                return
            if s.status == "DETACHED" or s.status == "FAILED":
                    
                # Update strm_selections count
                for r in self.circuits[s.circ_id].path: r.strm_selections += 1
                # Update failed count,reason_failed for exit
                r = self.circuits[s.circ_id].exit
                if not reason in r.reason_failed: r.reason_failed[reason] = 1
                else: r.reason_failed[reason]+=1
                r.strm_failed += 1

                # If reason=timeout, update suspected for all
                if lreason in ("TIMEOUT", "INTERNAL", "TORPROTOCOL", "DESTROY"):
                    for r in self.circuits[s.circ_id].path[:-1]:
                        r.strm_suspected += 1
                        if not reason in r.reason_suspected:
                            r.reason_suspected[reason] = 1
                        else: r.reason_suspected[reason]+=1
                else:
                    for r in self.circuits[s.circ_id].path[:-1]:
                        r.strm_uncounted += 1
            elif s.status == "CLOSED":
                # Always get both a closed and a failed.. 
                #   - Check if the circuit exists still
                if s.circ_id in self.circuits:
                    if lreason in ("TIMEOUT", "INTERNAL", "TORPROTOCOL" "DESTROY"):
                        for r in self.circuits[s.circ_id].path[:-1]:
                            r.strm_suspected += 1
                            if not reason in r.reason_suspected:
                                r.reason_suspected[reason] = 1
                            else: r.reason_suspected[reason]+=1
                    else:
                        for r in self.circuits[s.circ_id].path[:-1]:
                            r.strm_uncounted += 1
                        
                    r = self.circuits[s.circ_id].exit
                    if lreason == "DONE":
                        r.strm_succeeded += 1
                    else:
                        if not reason in r.reason_failed:
                            r.reason_failed[reason] = 1
                        else: r.reason_failed[reason]+=1
                        r.strm_failed += 1
            elif s.status == "SUCCEEDED":
                # Update strm_selections count
                # XXX: use SENTRESOLVE/SENTCONNECT instead?
                for r in self.circuits[s.circ_id].path: r.strm_selections += 1
        PathBuilder.stream_status_event(self, s)

    def ns_event(self, n):
        PathBuilder.ns_event(self, n)
        now = time.time()
        for ns in n.nslist:
            if not ns.idhex in self.routers:
                continue
            r = self.routers[ns.idhex]
            if "Running" in ns.flags:
                if not r.became_active_at:
                    r.became_active_at = now
                    r.total_hibernation_time += now - r.hibernated_at
                r.hibernated_at = 0
            else:
                if not r.hibernated_at:
                    r.hibernated_at = now
                    r.total_active_uptime += now - r.became_active_at
                r.became_active_at = 0
                

def clear_dns_cache(c):
    lines = c.sendAndRecv("SIGNAL CLEARDNSCACHE\r\n")
    for _,msg,more in lines:
        plog("DEBUG", msg)
 
def commandloop(s, c, h):
    s.write("220 Welcome to the Tor Metatroller "+mt_version+"! Try HELP for Info\r\n\r\n")
    while 1:
        buf = s.readline()
        if not buf: break
        
        m = re.search(r"^(\S+)(?:\s(\S+))?", buf)
        if not m:
            s.write("500 Guido insults you for thinking '"+buf+
                    "' could possibly be a metatroller command\r\n")
            continue
        (command, arg) = m.groups()
        if command == "GETLASTEXIT":
            # local assignment avoids need for lock w/ GIL
            # http://effbot.org/pyfaq/can-t-we-get-rid-of-the-global-interpreter-lock.htm
            # http://effbot.org/pyfaq/what-kinds-of-global-value-mutation-are-thread-safe.htm
            le = h.last_exit
            if le:
                s.write("250 LASTEXIT=$"+le.idhex.upper()+" ("+le.nickname+") OK\r\n")
            else:
                s.write("250 LASTEXIT=0 (0) OK\r\n")
        elif command == "NEWEXIT" or command == "NEWNYM":
            clear_dns_cache(c)
            h.new_nym = True # GIL hack
            plog("DEBUG", "Got new nym")
            s.write("250 NEWNYM OK\r\n")
        elif command == "GETDNSEXIT":
            pass # TODO: Takes a hostname? Or prints most recent?
        elif command == "RESETSTATS":
            s.write("250 OK\r\n")
        elif command == "ORDEREXITS":
            try:
                if arg:
                    order_exits = int(arg)
                    def notlambda(sm): sm.order_exits=order_exits
                    h.schedule_selmgr(notlambda)
                s.write("250 ORDEREXITS="+str(order_exits)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "USEALLEXITS":
            try:
                if arg:
                    use_all_exits = int(arg)
                    def notlambda(sm): sm.use_all_exits=use_all_exits
                    h.schedule_selmgr(notlambda)
                s.write("250 USEALLEXITS="+str(use_all_exits)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "PRECIRCUITS":
            try:
                if arg:
                    num_circuits = int(arg)
                    def notlambda(pb): pb.num_circuits=num_circuits
                    h.schedule_immediate(notlambda)
                s.write("250 PRECIRCUITS="+str(num_circuits)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "RESOLVEPORT":
            try:
                if arg:
                    resolve_port = int(arg)
                    def notlambda(pb): pb.resolve_port=resolve_port
                    h.schedule_immediate(notlambda)
                s.write("250 RESOLVEPORT="+str(resolve_port)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "PERCENTFAST":
            try:
                if arg:
                    percent_fast = int(arg)
                    def notlambda(sm): sm.percent_fast=percent_fast
                    h.schedule_selmgr(notlambda)
                s.write("250 PERCENTFAST="+str(percent_fast)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "PERCENTSKIP":
            try:
                if arg:
                    percent_skip = int(arg)
                    def notlambda(sm): sm.percent_skip=percent_skip
                    h.schedule_selmgr(notlambda)
                s.write("250 PERCENTSKIP="+str(percent_skip)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "BWCUTOFF":
            try:
                if arg:
                    min_bw = int(arg)
                    def notlambda(sm): sm.min_bw=min_bw
                    h.schedule_selmgr(notlambda)
                s.write("250 BWCUTOFF="+str(min_bw)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "UNIFORM":
            s.write("250 OK\r\n")
        elif command == "PATHLEN":
            try:
                if arg:
                    pathlen = int(arg)
                    # Technically this doesn't need a full selmgr update.. But
                    # the user shouldn't be changing it very often..
                    def notlambda(sm): sm.pathlen=pathlen
                    h.schedule_selmgr(notlambda)
                s.write("250 PATHLEN="+str(pathlen)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "SETEXIT":
            if arg:
                # XXX: Hrmm.. if teh user is a dumbass, this will fail silently
                def notlambda(sm): sm.exit_name=arg
                h.schedule_selmgr(notlambda)
                s.write("250 OK\r\n")
            else:
                s.write("510 Argument expected\r\n")
        elif command == "GUARDNODES":
            s.write("250 OK\r\n")
        elif command == "SAVESTATS":
            if arg: filename = arg
            else: filename = "./data/stats-"+time.strftime("20%y-%m-%d-%H:%M:%S")
            def notlambda(this): this.write_stats(filename)
            h.schedule_low_prio(notlambda)
            s.write("250 OK\r\n")
        elif command == "RESETSTATS":
            def notlambda(this): this.reset_stats()
            h.schedule_low_prio(notlambda)
            s.write("250 OK\r\n")
        elif command == "HELP":
            s.write("250 OK\r\n")
        else:
            s.write("510 Guido slaps you for thinking '"+command+
                    "' could possibly be a metatroller command\r\n")
    s.close()

def cleanup(c, s):
    c.set_option("__LeaveStreamsUnattached", "0")
    s.close()

def listenloop(c, h):
    """Loop that handles metatroller commands"""
    srv = ListenSocket(meta_host, meta_port)
    atexit.register(cleanup, *(c, srv))
    while 1:
        client = srv.accept()
        if not client: break
        thr = threading.Thread(None, lambda: commandloop(BufSock(client), c, h))
        thr.run()
    srv.close()

def startup():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((control_host,control_port))
    c = PathSupport.Connection(s)
    c.debug(file("control.log", "w"))
    c.authenticate()
    h = StatsHandler(c, __selmgr)
    c.set_event_handler(h)
    c.set_events([TorCtl.EVENT_TYPE.STREAM,
                  TorCtl.EVENT_TYPE.NS,
                  TorCtl.EVENT_TYPE.CIRC,
                  TorCtl.EVENT_TYPE.NEWDESC], True)
    c.set_option("__LeaveStreamsUnattached", "1")
    return (c,h)

def main(argv):
    listenloop(*startup())

if __name__ == '__main__':
    main(sys.argv)
