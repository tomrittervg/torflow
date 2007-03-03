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
        self.failed = 0
        self.suspected = 0
        self.circ_selections = 0
        self.strm_selections = 0
        self.unhibernated_at = 0
        self.active_uptime = 0
        self.reason_suspected = {}
        self.reason_failed = {}

class StatsHandler(PathSupport.PathBuilder):
    def __init__(self, c, slmgr):
        PathBuilder.__init__(self, c, slmgr, StatsRouter)

    def circ_status_event(self, event):
        PathBuilder.circ_status_event(self, event)

    def stream_status_event(self, event):
        PathBuilder.stream_status_event(self, event)

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
