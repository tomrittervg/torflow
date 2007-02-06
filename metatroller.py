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
import time
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

# TODO: Move these to config file
# TODO: Option to ignore guard flag
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
        self.built = False
        self.detached_cnt = 0
        self.used_cnt = 0
        self.created_at = time.time()
        self.pending_streams = [] # Which stream IDs are pending us

    
class Stream:
    def __init__(self, sid, host, port):
        self.sid = sid
        self.detached_from = [] # circ id #'s
        self.pending_circ = None
        self.circ = None
        self.host = host
        self.port = port

# TODO: Obviously we need other node selector implementations

class UniformSelector(TorCtl.NodeSelector):
    "Uniform node selection"
    # FIXME: Technically we should obey fast and valid
    def entry_chooser(self, path):
        r = random.choice(sorted_g)
        while r.idhex in path:
            r = random.choice(sorted_g)
        return r

    def middle_chooser(self, path):
        r = random.choice(sorted_r)
        while r.idhex in path:
            r = random.choice(sorted_r)
        return r

    def exit_chooser(self, path):
        allowed = []
        for r in sorted_r:
            if r.will_exit_to(self.to_ip, self.to_port):
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

    def attach_stream_any(self, stream, badcircs):
        for circ in circuits.itervalues():
            if circ.built and circ.cid not in badcircs:
                if circ.exit.will_exit_to(stream.host, stream.port):
                    self.c.attach_stream(stream.sid, circ.cid)
                    stream.pending_circ = None
                    stream.circ = circ
                    circ.used_cnt += 1
                    break
        else:
            circ = MetaCircuit(self.c.build_circuit(3,
                                 UniformSelector(stream.host, stream.port)))
            stream.pending_circ = circ
            circ.pending_streams.append(stream)
            circuits[circ.cid] = circ

    def circ_status(self, eventtype, circID, status, path, reason, remote):
        output = [eventtype, str(circID), status]
        if path: output.append(",".join(path))
        if reason: output.append("REASON=" + reason)
        if remote: output.append("REMOTE_REASON=" + remote)
        plog("DEBUG", " ".join(output))
        # Circuits we don't control get built by Tor
        if circID not in circuits: return
        if status == "FAILED" or status == "CLOSED":
            circ = circuits[circID]
            del circuits[circID]
            for stream in circ.pending_streams:
                self.attach_stream_any(stream, stream.detached_from)
        elif status == "BUILT":
            circuits[circID].built = True
            for stream in circuits[circID].pending_streams:
                self.c.attach_stream(stream.sid, circID)
                circuits[circID].used_cnt += 1

    def stream_status(self, eventtype, streamID, status, circID, target_host, target_port, reason, remote):
        output = [eventtype, str(streamID), status, str(circID), target_host,
                  str(target_port)]
        if reason: output.append("REASON=" + reason)
        if remote: output.append("REMOTE_REASON=" + remote)
        plog("DEBUG", " ".join(output))
        if not re.match(r"\d+.\d+.\d+.\d+", target_host):
            target_host = "255.255.255.255" # ignore DNS for exit policy check
        if status == "NEW" or status == "NEWRESOLVE":
            global circuits
            streams[streamID] = Stream(streamID, target_host, target_port)

            self.attach_stream_any(streams[streamID],
                                   streams[streamID].detached_from)
        elif status == "DETACHED":
            global circuits
            if streamID not in streams:
                plog("WARN", "Detached stream "+str(streamID)+" not found")
                streams[streamID] = Stream(streamID, target_host, target_port)
            # FIXME Stats
            if not circID:
                plog("WARN", "Stream "+str(streamID)+" detached from no circuit!")
            else:
                streams[streamID].detached_from.append(circID)

            self.attach_stream_any(streams[streamID],
                                   streams[streamID].detached_from)
        elif status == "FAILED" or status == "CLOSED":
            # FIXME stats
            if streams[streamID].pending_circ:
                streams[streamID].pending_circ.pending_streams.remove(streams[streamID])
            del streams[streamID]
        elif status == "REMAP":
            if streamID not in streams:
                plog("WARN", "Remap id "+str(streamID)+" not found")
            else:
                if not re.match(r"\d+.\d+.\d+.\d+", target_host):
                   target_host = "255.255.255.255"
                   plog("NOTICE", "Non-IP remap for "+str(streamID)+" to "
                                   + target_host)
                streams[streamID].host = target_host
                streams[streamID].port = target_port

    def ns(self, eventtype, nslist):
        read_routers(self.c, nslist)
        plog("DEBUG", "Read " + str(len(nslist)) + " NS dox => " 
             + str(len(sorted_r)) + " routers")
    
    def new_desc(self, eventtype, identities):
        for i in identities: # Is this too slow?
            read_routers(self.c, self.c.get_network_status("id/"+i))
        plog("DEBUG", "Read " + str(len(identities)) + " desc => " 
             + str(len(sorted_r)) + " routers")
        
def metaloop(c):
    """Loop that handles metatroller commands"""
    nslist = c.get_network_status()
    read_routers(c, nslist)
    plog("INFO", "Read "+str(len(sorted_r))+"/"+str(len(nslist))+" routers")
    # XXX: Loop for commands on socket

def main(argv):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((control_host,control_port))
    c = TorCtl.get_connection(s)
    c.set_event_handler(SnakeHandler(c))
    th = c.launch_thread()
    c.authenticate()
    atexit.register(lambda:
                       c.set_option("__LeaveStreamsUnattached", "0"))
    c.set_option("__LeaveStreamsUnattached", "1")
    c.set_events([TorCtl.EVENT_TYPE.STREAM,
                  TorCtl.EVENT_TYPE.NS,
                  TorCtl.EVENT_TYPE.CIRC,
                  TorCtl.EVENT_TYPE.NEWDESC], True)
    metaloop(c)
    th.join()

main(sys.argv)
