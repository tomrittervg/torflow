#!/usr/bin/python
# Metatroller. 

"""
Metatroller - Tor Meta controller
"""

import TorCtl
import atexit
import sys
import socket
import traceback
import re
import random
import datetime
import threading
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


version = "0.1.0-dev"

# TODO: Move these to config file
# TODO: Option to ignore guard flag
control_host = "127.0.0.1"
control_port = 9051
meta_host = "127.0.0.1"
meta_port = 9052
max_detach = 3
order_exits = False

# Thread shared variables. Relying on GIL for weak atomicity (really
# we only care about corruption.. GIL prevents that, so no locking needed)
# http://effbot.org/pyfaq/can-t-we-get-rid-of-the-global-interpreter-lock.htm
# http://effbot.org/pyfaq/what-kinds-of-global-value-mutation-are-thread-safe.htm

last_exit = None
resolve_port = 0
percent_fast = 100
percent_skip = 0
pathlen = 3
min_bw = 0
num_circuits = 1 # TODO: Use
use_all_exits = False
new_nym = False

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
        self.created_at = datetime.datetime.now()
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
#  - BwWeightedSelector
#  - Restrictors (puts self.r_is_ok() into list):
#    - Subnet16
#    - AvoidWastingExits
#    - VersionRange (Less than, greater than, in-range)
#    - OSSelector (ex Yes: Linux, *BSD; No: Windows, Solaris)
#    - OceanPhobicRestrictor (avoids Pacific Ocean or two atlantic crossings)
#      or ContinentRestrictor (avoids doing more than N continent crossings)
#      - Mathematical/empirical study of predecessor expectation
#        - If middle node is on the same continent as exit, exit learns nothing
#        - else, exit has a bias on the continent of origin of user
#          - Language and browser accept string determine this anyway
#    - ExitCountry
#    - AllCountry

class UniformSelector(TorCtl.NodeSelector):
    "Uniform node selection"

    next_exit_by_port = {} # class member (aka C++ 'static')

    def __init__(self, host, port):
        if not port:
            plog("DEBUG", "Using resolve: "+host+":"+str(resolve_port))
            port = resolve_port
        TorCtl.NodeSelector.__init__(self, host, port)
        self.pct_fast = percent_fast
        self.pct_skip = percent_skip
        self.min_bw = min_bw
        self.order_exits = order_exits
        self.all_exits = use_all_exits
        
    def r_is_ok(self, r):
        if r.bw < self.min_bw or not r.valid or not r.fast:
            return False
        else:
            return True

    def pick_r(self, r_list):
        idx = random.randint(len(r_list)*self.pct_skip/100,
                             len(r_list)*self.pct_fast/100)
        return r_list[idx]

    def entry_chooser(self, path):
        r = self.pick_r(sorted_g)
        while not self.r_is_ok(r) or r.idhex in path:
            r = self.pick_r(sorted_g)
        return r

    def middle_chooser(self, path):
        r = self.pick_r(sorted_r)
        while not self.r_is_ok(r) or r.idhex in path:
            r = self.pick_r(sorted_r)
        return r

    def exit_chooser(self, path):
        if self.order_exits:
            if self.to_port not in self.next_exit_by_port or self.next_exit_by_port[self.to_port] >= len(sorted_r):
                self.next_exit_by_port[self.to_port] = 0
                
            r = sorted_r[self.next_exit_by_port[self.to_port]]
            self.next_exit_by_port[self.to_port] += 1
            while not r.will_exit_to(self.to_ip, self.to_port):
                r = sorted_r[self.next_exit_by_port[self.to_port]]
                self.next_exit_by_port[self.to_port] += 1
                if self.next_exit_by_port[self.to_port] >= len(sorted_r):
                    self.next_exit_by_port[self.to_port] = 0
            return r

        # FIXME: This should apply to ORDEREXITS (for speedracer?)
        if self.all_exits:
            minbw = self.min_bw
            pct_fast = self.pct_fast
            pct_skip = self.pct_skip
            self.min_bw = self.pct_skip = 0
            self.pct_fast = 100
     
        allowed = []
        for r in sorted_r:
            if self.r_is_ok(r) and not r.badexit and r.will_exit_to(self.to_ip, self.to_port):
                allowed.append(r)
        r = self.pick_r(allowed)
        while r.idhex in path:
            r = self.pick_r(allowed)

        if self.all_exits:
            self.min_bw = minbw
            self.pct_fast = pct_fast
            self.pct_skip = pct_skip
 
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

# TODO: Make passive mode so people can get aggregate node reliability 
# stats for normal usage without us attaching streams

# Make eventhandler
class SnakeHandler(TorCtl.EventHandler):
    def __init__(self, c):
        TorCtl.EventHandler.__init__(self)
        self.c = c

    def attach_stream_any(self, stream, badcircs):
        # Newnym, and warn if not built plus pending
        unattached_streams = [stream]
        global new_nym
        if new_nym:
            new_nym = False
            plog("DEBUG", "Obeying new nym")
            for key in circuits.keys():
                if len(circuits[key].pending_streams):
                    plog("WARN", "New nym called, destroying circuit "+str(key)
                         +" with "+str(len(circuits[key].pending_streams))
                         +" pending streams")
                    unattached_streams.extend(circuits[key].pending_streams)
                # FIXME: Consider actually closing circ if no streams.
                # Or send Tor a SIGNAL NEWNYM and let it do it.
                del circuits[key]
            
        for circ in circuits.itervalues():
            if circ.built and circ.cid not in badcircs:
                if circ.exit.will_exit_to(stream.host, stream.port):
                    self.c.attach_stream(stream.sid, circ.cid)
                    stream.pending_circ = circ # Only one stream possible here
                    circ.pending_streams.append(stream)
                    break
        else:
            circ = MetaCircuit(self.c.build_circuit(pathlen,
                                 UniformSelector(stream.host, stream.port)))
            for u in unattached_streams:
                plog("DEBUG", "Attach pending build: "+str(u.sid))
                u.pending_circ = circ
            circ.pending_streams.extend(unattached_streams)
            circuits[circ.cid] = circ
        global last_exit # Last attempted exit
        last_exit = circ.exit

    def circ_status(self, eventtype, circID, status, path, reason, remote):
        output = [eventtype, str(circID), status]
        if path: output.append(",".join(path))
        if reason: output.append("REASON=" + reason)
        if remote: output.append("REMOTE_REASON=" + remote)
        plog("DEBUG", " ".join(output))
        # Circuits we don't control get built by Tor
        if circID not in circuits:
            plog("DEBUG", "Ignoring circ " + str(circID))
            return
        if status == "FAILED" or status == "CLOSED":
            circ = circuits[circID]
            del circuits[circID]
            for stream in circ.pending_streams:
                plog("DEBUG", "Finding new circ for " + str(stream.sid))
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
            # FIXME Stats (differentiate Resolved streams also..)
            if not circID:
                plog("WARN", "Stream "+str(streamID)+" detached from no circuit!")
            else:
                streams[streamID].detached_from.append(circID)

            
            if streams[streamID] in streams[streamID].pending_circ.pending_streams:
                streams[streamID].pending_circ.pending_streams.remove(streams[streamID])
            streams[streamID].pending_circ = None
            self.attach_stream_any(streams[streamID],
                                   streams[streamID].detached_from)
        elif status == "SUCCEEDED":
            if streamID not in streams:
                plog("NOTICE", "Succeeded stream "+str(streamID)+" not found")
                return
            streams[streamID].circ = streams[streamID].pending_circ
            streams[streamID].circ.pending_streams.remove(streams[streamID])
            streams[streamID].pending_circ = None
            streams[streamID].circ.used_cnt += 1
        elif status == "FAILED" or status == "CLOSED":
            # FIXME stats
            if status == "FAILED": # We get failed and closed for each stream
                return
            if streamID not in streams:
                plog("NOTICE", "Failed stream "+str(streamID)+" not found")
                return
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
        plog("DEBUG", "Read " + str(len(nslist)) + eventtype + " => " 
             + str(len(sorted_r)) + " routers")
    
    def new_desc(self, eventtype, identities):
        for i in identities: # Is this too slow?
            read_routers(self.c, self.c.get_network_status("id/"+i))
        plog("DEBUG", "Read " + str(len(identities)) + eventtype + " => " 
             + str(len(sorted_r)) + " routers")
        

def commandloop(s):
    s.write("220 Welcome to the Tor Metatroller "+version+"! Try HELP for Info\r\n\r\n")
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
            le = last_exit # Consistency (avoids need for lock w/ GIL)
            s.write("250 LASTEXIT=$"+le.idhex.upper()+" ("+le.name+") OK\r\n")
        elif command == "NEWEXIT" or command == "NEWNYM":
            global new_nym
            new_nym = True
            plog("DEBUG", "Got new nym")
            s.write("250 NEWNYM OK\r\n")
        elif command == "GETDNSEXIT":
            pass # TODO
        elif command == "RESETSTATS":
            s.write("250 OK\r\n")
        elif command == "ORDEREXITS":
            global order_exits
            try:
                if arg: order_exits = int(arg)
                s.write("250 ORDEREXITS="+str(order_exits)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "USEALLEXITS":
            global use_all_exits
            try:
                if arg: use_all_exits = int(arg)
                s.write("250 USEALLEXITS="+str(use_all_exits)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "PRECIRCUITS":
            global num_circuits
            try:
                if arg: num_circuits = int(arg)
                s.write("250 PRECIRCUITS="+str(num_circuits)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "RESOLVEPORT":
            global resolve_port
            try:
                if arg: resolve_port = int(arg)
                s.write("250 RESOLVEPORT="+str(resolve_port)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "PERCENTFAST":
            global percent_fast
            try:
                if arg: percent_fast = int(arg)
                s.write("250 PERCENTFAST="+str(percent_fast)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "PERCENTSKIP":
            global percent_skip
            try:
                if arg: percent_skip = int(arg)
                s.write("250 PERCENTSKIP="+str(percent_skip)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "BWCUTOFF":
            global min_bw
            try:
                if arg: min_bw = int(arg)
                s.write("250 BWCUTOFF="+str(min_bw)+" OK\r\n")
            except ValueError:
                s.write("510 Integer expected\r\n")
        elif command == "UNIFORM":
            s.write("250 OK\r\n")
        elif command == "PATHLEN":
            global pathlen
            try:
                if arg: pathlen = int(arg)
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

def listenloop(c):
    """Loop that handles metatroller commands"""
    nslist = c.get_network_status()
    read_routers(c, nslist)
    c.set_option("__LeaveStreamsUnattached", "1")
    plog("INFO", "Read "+str(len(sorted_r))+"/"+str(len(nslist))+" routers")
    srv = ListenSocket(meta_host, meta_port)
    atexit.register(cleanup, *(c, srv))
    while 1:
        client = srv.accept()
        if not client: break
        thr = threading.Thread(None, lambda: commandloop(BufSock(client)))
        thr.run()
    srv.close()

def main(argv):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((control_host,control_port))
    c = TorCtl.get_connection(s)
    c.set_event_handler(SnakeHandler(c))
    c.launch_thread()
    c.authenticate()
    c.set_events([TorCtl.EVENT_TYPE.STREAM,
                  TorCtl.EVENT_TYPE.NS,
                  TorCtl.EVENT_TYPE.CIRC,
                  TorCtl.EVENT_TYPE.NEWDESC], True)
    listenloop(c)

if __name__ == '__main__':
    main(sys.argv)
