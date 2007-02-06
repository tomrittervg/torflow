#!/usr/bin/python
# Metatroller. 

"""
Metatroller - Tor Meta controller
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

routers = {} # indexed by idhex
name_to_key = {}
key_to_name = {}

total_r_bw = 0
sorted_r = []
sorted_g = []
total_g_bw = 0

circuits = {} # map from ID # to circuit object
streams = {} # map from stream id to circuit

exit_port_idx = {} # Used in ordered exits mode

# XXX: Option to ignore guard flag

# XXX: Move these to config file
control_host = "127.0.0.1"
control_port = 9061
max_detach = 3


# Technically we could just add member vars as we need them, but this
# is a bit more clear
class MetaRouter(TorCtl.Router):
    def __init__(self, router): # Promotion constructor :)
        self.__dict__ = router.__dict__
        self.failed = 0
        self.suspected = 0
        self.circ_selections = 0
        self.strm_selections = 0
        self.reason_suspected = {}
        self.reason_failed = {}

class MetaCircuit(TorCtl.Circuit):
    def __init__(self, circuit): # Promotion
        self.__dict__ = circuit.__dict__
        self.detached_cnt = 0
        self.used_cnt = 0
        self.created_at = 0
    
class Stream:
    def __init__(self):
        self.detached_from = [] # circ id #'s
        self.detached_cnt = 0

# XXX: Technically we should obey fast and valid????
def choose_entry_uniform(path):
    r = random.choice(sorted_g)
    while r.idhex in path:
        r = random.choice(sorted_g)
    return r

def choose_middle_uniform(path):
    r = random.choice(sorted_r)
    while r.idhex in path:
        r = random.choice(sorted_r)
    return r

def choose_exit_uniform(path, target_ip, target_port):
    allowed = []
    for r in sorted_r:
        if r.will_exit_to(target_ip, target_port):
            allowed.append(r)
    r = random.choice(allowed)
    while r.idhex in path:
        r = random.choice(allowed)
    return r
 
def read_routers(c, nslist):
    bad_key = 0
    for ns in nslist:
        try:
            key_to_name[ns.idhex] = ns.name
            name_to_key[ns.name] = ns.idhex
            r = MetaRouter(c.get_router(ns))
            if ns.idhex in routers:
                if routers[ns.idhex].name != r.name:
                    plog("NOTICE", "Router "+r.idhex+" changed names from "
                         +routers[ns.idhex].name+" to "+r.name)
                sorted_r.remove(routers[ns.idhex])
            routers[ns.idhex] = r
            sorted_r.append(r)
        except TorCtl.ErrorReply:
            bad_key += 1
            if "Running" in ns.flags:
                plog("NOTICE", "Running router "+ns.name+"="
                     +ns.idhex+" has no descriptor")
            pass
        except:
            traceback.print_exception(*sys.exc_info())
            continue
    sorted_r.sort(lambda x, y: cmp(y.bw, x.bw))

    global total_r_bw, total_g_bw # lame....
    for r in sorted_r:
        if not r.down:
            total_r_bw += r.bw
            if r.guard and r.valid:
                total_g_bw += r.bw
                sorted_g.append(r)

# Make eventhandler
class SnakeHandler(TorCtl.EventHandler):
    def __init__(self, c):
        TorCtl.EventHandler.__init__(self)
        self.c = c

    def circ_status(self, eventtype, circID, status, path, reason, remote):
        output = [eventtype, str(circID), status]
        if path: output.append(",".join(path))
        if reason: output.append("REASON=" + reason)
        if remote: output.append("REMOTE_REASON=" + remote)
        plog("DEBUG", " ".join(output))

    def stream_status(self, eventtype, streamID, status, circID, target_host, target_port, reason, remote):
        output = [eventtype, str(streamID), status, str(circID), target_host,
str(target_port)]
        if reason: output.append("REASON=" + reason)
        if remote: output.append("REMOTE_REASON=" + remote)
        plog("DEBUG", " ".join(output))
        if not re.match(r"\d+.\d+.\d+.\d+", target_host):
            target_host = "255.255.255.255" # ignore DNS for exit policy check
        if status == "NEW":
            attach_circ = 0
            global circuits
            for circ in circuits.itervalues():
                if circ.exit.will_exit_to(target_host, target_port):
                    attach_circ = circ
                    break
            else:
                attach_circ = MetaCircuit(
                                self.c.build_circuit(3, choose_entry_uniform,
                                      choose_middle_uniform,
                                      lambda path:
                                          choose_exit_uniform(path,
                                          target_host, target_port)))
                circuits[attach_circ.cid] = attach_circ
            # TODO: attach
        elif status == "DETACHED":
            pass
        elif status == "FAILED":
            pass

    def ns(self, eventtype, nslist):
        read_routers(self.c, nslist)
        plog("DEBUG", "Read " + str(len(nslist)) + " NS dox => " 
             + str(len(sorted_r)) + " routers")
    
    def new_desc(self, eventtype, identities):
        for i in identities: # Is this too slow?
            read_routers(self.c, self.c.get_network_status("id/"+i))
        plog("DEBUG", "Read " + str(len(identities)) + " desc => " 
             + str(len(sorted_r)) + " routers")
        
def deconf():
    pass

def metaloop(c):
    """Loop that handles metatroller commands"""
    nslist = c.get_network_status()
    read_routers(c, nslist)
    plog("INFO", "Read "+str(len(sorted_r))+"/"+str(len(nslist))+" routers")

def main(argv):
    atexit.register(deconf)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((control_host,control_port))
    c = TorCtl.get_connection(s)
    c.set_event_handler(SnakeHandler(c))
    th = c.launch_thread()
    c.authenticate()
    c.set_events([TorCtl.EVENT_TYPE.STREAM,
                  TorCtl.EVENT_TYPE.NS,
                  TorCtl.EVENT_TYPE.CIRC,
                  TorCtl.EVENT_TYPE.NEWDESC], True)
    metaloop(c)
    th.join()

main(sys.argv)
