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

selmgr = PathSupport.SelectionManager(
            resolve_port=0,
            num_circuits=1,
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
        self.circ_failed = 0
        self.circ_succeeded = 0
        self.circ_suspected = 0
        self.circ_selections = 0 # above 3 should add to this
        self.strm_failed = 0 # Only exits should have these
        self.strm_succeeded = 0
        self.strm_suspected = 0
        self.strm_selections = 0 # above 3 should add to this
        self.reason_suspected = {}
        self.reason_failed = {}
        self.became_active_at = 0
        self.total_active_uptime = 0
        self.max_bw = 0
        self.min_bw = 0
        self.avg_bw = 0

class StatsHandler(PathSupport.PathBuilder):
    def __init__(self, c, slmgr):
        PathBuilder.__init__(self, c, slmgr, StatsRouter)
    
    def heartbeat_event(self, event):
        PathBuilder.heartbeat_event(self, event)

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
            reason = c.status+":"+lreason+":"+rreason
            if c.status == "FAILED":
                # update selection count
                for r in self.circuits[c.circ_id].path: r.circ_selections += 1

                # Count failed
                for r in self.circuits[c.circ_id].path[len(c.path)-1:len(c.path)+1]:
                    r.circ_failed += 1
                    if not reason in r.reason_failed: r.reason_failed[reason] = 1
                    else: r.reason_failed[reason]+=1
                
                # Don't count if failed was set this round, don't set 
                # suspected..
                if len(c.path)-2 < 0: end_susp = 0
                else: end_susp = len(c.path)-2
                for r in self.circuits[c.circ_id].path[:end_susp]:
                    r.circ_suspected += 1
                    if not reason in r.reason_suspected:
                        r.reason_suspected[reason] = 1
                    else: r.reason_suspected[reason]+=1
            elif c.status == "CLOSED":
                # Since PathBuilder deletes the circuit on a failed, 
                # we only get this for a clean close
                # Update circ_selections count
                for r in self.circuits[c.circ_id].path: r.circ_selections += 1
                
                if lreason in ("REQUESTED", "FINISHED", "ORIGIN"):
                    r.circ_succeeded += 1
                else:
                    for r in self.circuits[c.circ_id].path:
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
            reason = s.status+":"+lreason+":"+rreason+":"+self.streams[s.strm_id].kind
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
            elif s.status == "CLOSED":
                # Always get both a closed and a failed.. 
                #   - Check if the circuit exists still
                if s.circ_id in self.circuits:
                    if lreason in ("TIMEOUT", "INTERNAL", "TORPROTOCOL", "DESTROY"):
                        for r in self.circuits[s.circ_id].path[:-1]:
                            r.strm_suspected += 1
                            if not reason in r.reason_suspected:
                                r.reason_suspected[reason] = 1
                            else: r.reason_suspected[reason]+=1
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
        for ns in n.nslist:
            if not ns.idhex in self.routers:
                continue
            if "Running" in ns.flags:
                if not self.routers[ns.idhex].became_active_at:
                    self.routers[ns.idhex].became_active_at = time.time()
            else:
                self.routers[ns.idhex].total_active_uptime += \
                    (time.time() - self.routers[ns.idhex].became_active_at)
                self.routers[ns.idhex].became_active_at = 0
                

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
            # local assignment avoids need for lock w/ GIL:
            le = h.selmgr.last_exit
            s.write("250 LASTEXIT=$"+le.idhex.upper()+" ("+le.nickname+") OK\r\n")
        elif command == "NEWEXIT" or command == "NEWNYM":
            clear_dns_cache(c)
            newmgr = copy.copy(h.selupdate)
            newmgr.new_nym = True
            h.update_selmgr(newmgr)
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
                    newmgr = copy.copy(h.selupdate)
                    newmgr.order_exits = order_exits
                    h.update_selmgr(newmgr)
                s.write("250 ORDEREXITS="+str(order_exits)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "USEALLEXITS":
            try:
                if arg:
                    use_all_exits = int(arg)
                    newmgr = copy.copy(h.selupdate)
                    newmgr.use_all_exits = use_all_exits
                    h.update_selmgr(newmgr)
                s.write("250 USEALLEXITS="+str(use_all_exits)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "PRECIRCUITS":
            try:
                if arg:
                    num_circuits = int(arg)
                    newmgr = copy.copy(h.selupdate)
                    newmgr.num_circuits = num_circuits
                    h.update_selmgr(newmgr)
                s.write("250 PRECIRCUITS="+str(num_circuits)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "RESOLVEPORT":
            try:
                if arg:
                    resolve_port = int(arg)
                    newmgr = copy.copy(h.selupdate)
                    newmgr.resolve_port = resolve_port
                    h.update_selmgr(newmgr)
                s.write("250 RESOLVEPORT="+str(resolve_port)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "PERCENTFAST":
            try:
                if arg:
                    percent_fast = int(arg)
                    newmgr = copy.copy(h.selupdate)
                    newmgr.percent_fast = percent_fast
                    h.update_selmgr(newmgr)
                s.write("250 PERCENTFAST="+str(percent_fast)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "PERCENTSKIP":
            try:
                if arg:
                    percent_skip = int(arg)
                    newmgr = copy.copy(h.selupdate)
                    newmgr.percent_skip = percent_skip
                    h.update_selmgr(newmgr)
                s.write("250 PERCENTSKIP="+str(percent_skip)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "BWCUTOFF":
            try:
                if arg:
                    min_bw = int(arg)
                    newmgr = copy.copy(h.selupdate)
                    newmgr.min_bw = min_bw
                    h.update_selmgr(newmgr)
                s.write("250 BWCUTOFF="+str(min_bw)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "UNIFORM":
            s.write("250 OK\r\n")
        elif command == "PATHLEN":
            try:
                if arg:
                    pathlen = int(arg)
                    newmgr = copy.copy(h.selupdate)
                    newmgr.pathlen = pathlen
                    h.update_selmgr(newmgr)
                s.write("250 PATHLEN="+str(pathlen)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "SETEXIT":
            s.write("250 OK\r\n")
        elif command == "GUARDNODES":
            s.write("250 OK\r\n")
        elif command == "SAVESTATS":
            s.write("250 OK\r\n")
        elif command == "RESETSTATS":
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
    h = StatsHandler(c, selmgr)
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
