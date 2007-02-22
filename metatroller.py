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
import struct
from TorUtil import *

routers = {} # indexed by idhex
name_to_key = {}
key_to_name = {}

sorted_r = []

circuits = {} # map from ID # to circuit object
streams = {} # map from stream id to circuit

version = "0.1.0-dev"

# TODO: Move these to config file
# TODO: Option to ignore guard flag
control_host = "127.0.0.1"
control_port = 9061
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

# TODO: We still need more path support implementations
#  - BwWeightedGenerator
#  - NodeRestrictions:
#    - Uptime
#    - GeoIP
#      - NodeCountry
#  - PathRestrictions
#    - Family
#    - GeoIP:
#      - OceanPhobicRestrictor (avoids Pacific Ocean or two atlantic crossings)
#        or ContinentRestrictor (avoids doing more than N continent crossings)
#        - Mathematical/empirical study of predecessor expectation
#          - If middle node on the same continent as exit, exit learns nothing
#          - else, exit has a bias on the continent of origin of user
#            - Language and browser accept string determine this anyway

class PercentileRestriction(TorCtl.NodeRestriction):
    """If used, this restriction MUST be FIRST in the RestrictionList."""
    def __init__(self, pct_skip, pct_fast, r_list):
        self.pct_skip = pct_skip
        self.pct_fast = pct_fast
        self.sorted_r = r_list
        self.position = 0

    def reset(self, r_list):
        self.sorted_r = r_list
        self.position = 0
        
    def r_is_ok(self, r):
        ret = True
        if self.position == len(self.sorted_r):
            self.position = 0
            plog("WARN", "Resetting PctFastRestriction")
        if self.position != self.sorted_r.index(r): # XXX expensive?
            plog("WARN", "Router"+r.name+" at mismatched index: "
                         +self.position+" vs "+self.sorted_r.index(r))
        
        if self.position < len(self.sorted_r)*self.pct_skip/100:
            ret = False
        elif self.position > len(self.sorted_r)*self.pct_fast/100:
            ret = False
        
        self.position += 1
        return ret
        
class OSRestriction(TorCtl.NodeRestriction):
    def __init__(self, ok, bad=[]):
        self.ok = ok
        self.bad = bad

    def r_is_ok(self, r):
        for y in self.ok:
            if re.search(y, r.os):
                return True
        for b in self.bad:
            if re.search(b, r.os):
                return False
        if self.ok: return False
        if self.bad: return True

class ConserveExitsRestriction(TorCtl.NodeRestriction):
    def r_is_ok(self, r): return not "Exit" in r.flags

class FlagsRestriction(TorCtl.NodeRestriction):
    def __init__(self, mandatory, forbidden=[]):
        self.mandatory = mandatory
        self.forbidden = forbidden

    def r_is_ok(self, router):
        for m in self.mandatory:
            if not m in router.flags: return False
        for f in self.forbidden:
            if f in router.flags: return False
        return True
        

class MinBWRestriction(TorCtl.NodeRestriction):
    def __init__(self, minbw):
        self.min_bw = minbw

    def r_is_ok(self, router): return router.bw >= self.min_bw
     
class VersionIncludeRestriction(TorCtl.NodeRestriction):
    def __init__(self, eq):
        self.eq = map(TorCtl.RouterVersion, eq)
    
    def r_is_ok(self, router):
        for e in self.eq:
            if e == router.version:
                return True
        return False


class VersionExcludeRestriction(TorCtl.NodeRestriction):
    def __init__(self, exclude):
        self.exclude = map(TorCtl.RouterVersion, exclude)
    
    def r_is_ok(self, router):
        for e in self.exclude:
            if e == router.version:
                return False
        return True

class VersionRangeRestriction(TorCtl.NodeRestriction):
    def __init__(self, gr_eq, less_eq=None):
        self.gr_eq = TorCtl.RouterVersion(gr_eq)
        if less_eq: self.less_eq = TorCtl.RouterVersion(less_eq)
        else: self.less_eq = None
    

    def r_is_ok(self, router):
        return (not self.gr_eq or router.version >= self.gr_eq) and \
                (not self.less_eq or router.version <= self.less_eq)

class ExitPolicyRestriction(TorCtl.NodeRestriction):
    def __init__(self, to_ip, to_port):
        self.to_ip = to_ip
        self.to_port = to_port

    def r_is_ok(self, r):
        return r.will_exit_to(self.to_ip, self.to_port)

class AndRestriction(TorCtl.NodeRestriction):
    def __init__(self, a, b):
        self.a = a
        self.b = b

    def r_is_ok(self, r): return self.a.r_is_ok(r) and self.b.r_is_ok(r)

class OrRestriction(TorCtl.NodeRestriction):
    def __init__(self, a, b):
        self.a = a
        self.b = b

    def r_is_ok(self, r): return self.a.r_is_ok(r) or self.b.r_is_ok(r)

class NotRestriction(TorCtl.NodeRestriction):
    def __init__(self, a):
        self.a = a

    def r_is_ok(self, r): return not self.a.r_is_ok(r)

class Subnet16Restriction(TorCtl.PathRestriction):
    def r_is_ok(self, path, router):
        mask16 = struct.unpack(">I", socket.inet_aton("255.255.0.0"))[0]
        ip16 = router.ip & mask16
        for r in path:
            if ip16 == (r.ip & mask16):
                return False
        return True

class UniqueRestriction(TorCtl.PathRestriction):
    def r_is_ok(self, path, r): return not r in path

class UniformGenerator(TorCtl.NodeGenerator):
    def next_r(self):
        while not self.all_chosen():
            r = random.choice(self.routers)
            self.mark_chosen(r)
            yield r

class OrderedExitGenerator(TorCtl.NodeGenerator):
    next_exit_by_port = {} # class member (aka C++ 'static')
    def __init__(self, restriction_list, to_port):
        self.to_port = to_port
        TorCtl.NodeGenerator.__init__(self, restriction_list)

    def rewind(self):
        TorCtl.NodeGenerator.rewind(self)
        if self.to_port not in self.next_exit_by_port or not self.next_exit_by_port[self.to_port]:
            self.next_exit_by_port[self.to_port] = 0
            self.last_idx = len(self.routers)
        else:
            self.last_idx = self.next_exit_by_port[self.to_port]
   
    # Just in case: 
    def mark_chosen(self, r): raise NotImplemented()
    def all_chosen(self): raise NotImplemented()

    def next_r(self):
        while True: # A do..while would be real nice here..
            if self.next_exit_by_port[self.to_port] >= len(sorted_r):
                self.next_exit_by_port[self.to_port] = 0
            r = self.routers[self.next_exit_by_port[self.to_port]]
            self.next_exit_by_port[self.to_port] += 1
            yield r
            if self.last_idx == self.next_exit_by_port[self.to_port]:
                break
        
# TODO: Make passive mode so people can get aggregate node reliability 
# stats for normal usage without us attaching streams

# Make eventhandler
class SnakeHandler(TorCtl.EventHandler):
    def __init__(self, c):
        TorCtl.EventHandler.__init__(self)
        self.c = c
        nslist = c.get_network_status()
        self.read_routers(nslist)
        plog("INFO", "Read "+str(len(sorted_r))+"/"+str(len(nslist))+" routers")
        self.path_rstr = TorCtl.PathRestrictionList(
                 [Subnet16Restriction(), UniqueRestriction()])
        self.entry_rstr = TorCtl.NodeRestrictionList(
            [PercentileRestriction(percent_skip, percent_fast, sorted_r),
             ConserveExitsRestriction(),
             FlagsRestriction(["Guard", "Valid", "Running"], [])], sorted_r)
        self.mid_rstr = TorCtl.NodeRestrictionList(
            [PercentileRestriction(percent_skip, percent_fast, sorted_r),
             ConserveExitsRestriction(),
             FlagsRestriction(["Valid", "Running"], [])], sorted_r)
        self.exit_rstr = TorCtl.NodeRestrictionList(
            [PercentileRestriction(percent_skip, percent_fast, sorted_r),
             FlagsRestriction(["Valid", "Running", "Exit"], ["BadExit"])],
             sorted_r)
        self.path_selector = TorCtl.PathSelector(
             UniformGenerator(self.entry_rstr),
             UniformGenerator(self.mid_rstr),
             OrderedExitGenerator(self.exit_rstr, 80), self.path_rstr)

    def read_routers(self, nslist):
        bad_key = 0
        for ns in nslist:
            try:
                key_to_name[ns.idhex] = ns.nickname
                name_to_key[ns.nickname] = ns.idhex
                r = MetaRouter(self.c.get_router(ns))
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
                    plog("NOTICE", "Running router "+ns.nickname+"="
                         +ns.idhex+" has no descriptor")
                pass
            except:
                traceback.print_exception(*sys.exc_info())
                continue
    
        sorted_r.sort(lambda x, y: cmp(y.bw, x.bw))

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
                    try:
                        self.c.attach_stream(stream.sid, circ.cid)
                        stream.pending_circ = circ # Only one possible here
                        circ.pending_streams.append(stream)
                    except TorCtl.ErrorReply, e:
                        # No need to retry here. We should get the failed
                        # event for either the circ or stream next
                        plog("NOTICE", "Error attaching stream: "+str(e.args))
                        return
                    break
        else:
            circ = None
            while circ == None:
                self.exit_rstr.del_restriction(ExitPolicyRestriction)
                self.exit_rstr.add_restriction(
                     ExitPolicyRestriction(stream.host, stream.port))
                try:
                    circ = MetaCircuit(self.c.build_circuit(pathlen,
                                    self.path_selector))
                except TorCtl.ErrorReply, e:
                    # FIXME: How come some routers are non-existant? Shouldn't
                    # we have gotten an NS event to notify us they
                    # disappeared?
                    plog("NOTICE", "Error building circ: "+str(e.args))
            for u in unattached_streams:
                plog("DEBUG",
                     "Attaching "+str(u.sid)+" pending build of "+str(circ.cid))
                u.pending_circ = circ
            circ.pending_streams.extend(unattached_streams)
            circuits[circ.cid] = circ
        global last_exit # Last attempted exit
        last_exit = circ.exit

    def heartbeat_event(self):
        # XXX: Config updates to selectors
        pass

    def circ_status_event(self, c):
        output = [c.event_name, str(c.circ_id), c.status]
        if c.path: output.append(",".join(c.path))
        if c.reason: output.append("REASON=" + c.reason)
        if c.remote_reason: output.append("REMOTE_REASON=" + c.remote_reason)
        plog("DEBUG", " ".join(output))
        # Circuits we don't control get built by Tor
        if c.circ_id not in circuits:
            plog("DEBUG", "Ignoring circ " + str(c.circ_id))
            return
        if c.status == "FAILED" or c.status == "CLOSED":
            circ = circuits[c.circ_id]
            del circuits[c.circ_id]
            for stream in circ.pending_streams:
                plog("DEBUG", "Finding new circ for " + str(stream.sid))
                self.attach_stream_any(stream, stream.detached_from)
        elif c.status == "BUILT":
            circuits[c.circ_id].built = True
            for stream in circuits[c.circ_id].pending_streams:
                self.c.attach_stream(stream.sid, c.circ_id)
                circuits[c.circ_id].used_cnt += 1

    def stream_status_event(self, s):
        output = [s.event_name, str(s.strm_id), s.status, str(s.circ_id),
                  s.target_host, str(s.target_port)]
        if s.reason: output.append("REASON=" + s.reason)
        if s.remote_reason: output.append("REMOTE_REASON=" + s.remote_reason)
        plog("DEBUG", " ".join(output))
        if not re.match(r"\d+.\d+.\d+.\d+", s.target_host):
            s.target_host = "255.255.255.255" # ignore DNS for exit policy check
        if s.status == "NEW" or s.status == "NEWRESOLVE":
            global circuits
            streams[s.strm_id] = Stream(s.strm_id, s.target_host, s.target_port)

            self.attach_stream_any(streams[s.strm_id],
                                   streams[s.strm_id].detached_from)
        elif s.status == "DETACHED":
            global circuits
            if s.strm_id not in streams:
                plog("WARN", "Detached stream "+str(s.strm_id)+" not found")
                streams[s.strm_id] = Stream(s.strm_id, s.target_host,
                                            s.target_port)
            # FIXME Stats (differentiate Resolved streams also..)
            if not s.circ_id:
                plog("WARN", "Stream "+str(s.strm_id)+" detached from no circuit!")
            else:
                streams[s.strm_id].detached_from.append(s.circ_id)

            
            if streams[s.strm_id] in streams[s.strm_id].pending_circ.pending_streams:
                streams[s.strm_id].pending_circ.pending_streams.remove(streams[s.strm_id])
            streams[s.strm_id].pending_circ = None
            self.attach_stream_any(streams[s.strm_id],
                                   streams[s.strm_id].detached_from)
        elif s.status == "SUCCEEDED":
            if s.strm_id not in streams:
                plog("NOTICE", "Succeeded stream "+str(s.strm_id)+" not found")
                return
            streams[s.strm_id].circ = streams[s.strm_id].pending_circ
            streams[s.strm_id].circ.pending_streams.remove(streams[s.strm_id])
            streams[s.strm_id].pending_circ = None
            streams[s.strm_id].circ.used_cnt += 1
        elif s.status == "FAILED" or s.status == "CLOSED":
            # FIXME stats
            if s.strm_id not in streams:
                plog("NOTICE", "Failed stream "+str(s.strm_id)+" not found")
                return

            if not s.circ_id:
                plog("WARN", "Stream "+str(s.strm_id)+" failed from no circuit!")

            # We get failed and closed for each stream. OK to return 
            # and let the closed do the cleanup
            # (FIXME: be careful about double stats)
            if s.status == "FAILED":
                # Avoid busted circuits that will not resolve or carry
                # traffic. FIXME: Failed count before doing this?
                if s.circ_id in circuits: del circuits[s.circ_id]
                else: plog("WARN","Failed stream on unknown circ "+str(s.circ_id))
                return

            if streams[s.strm_id].pending_circ:
                streams[s.strm_id].pending_circ.pending_streams.remove(streams[s.strm_id])
            del streams[s.strm_id]
        elif s.status == "REMAP":
            if s.strm_id not in streams:
                plog("WARN", "Remap id "+str(s.strm_id)+" not found")
            else:
                if not re.match(r"\d+.\d+.\d+.\d+", s.target_host):
                    s.target_host = "255.255.255.255"
                    plog("NOTICE", "Non-IP remap for "+str(s.strm_id)+" to "
                                   + s.target_host)
                streams[s.strm_id].host = s.target_host
                streams[s.strm_id].port = s.target_port


    def ns_event(self, n):
        self.read_routers(n.nslist)
        plog("DEBUG", "Read " + str(len(n.nslist))+" NS => " 
             + str(len(sorted_r)) + " routers")
        self.entry_rstr.update_routers(sorted_r)
        self.mid_rstr.update_routers(sorted_r)
        self.exit_rstr.update_routers(sorted_r)
    
    def new_desc_event(self, d):
        for i in d.idlist: # Is this too slow?
            self.read_routers(self.c.get_network_status("id/"+i))
        plog("DEBUG", "Read " + str(len(d.idlist))+" Desc => " 
             + str(len(sorted_r)) + " routers")
        self.entry_rstr.update_routers(sorted_r)
        self.mid_rstr.update_routers(sorted_r)
        self.exit_rstr.update_routers(sorted_r)
        

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
    srv = ListenSocket(meta_host, meta_port)
    atexit.register(cleanup, *(c, srv))
    while 1:
        client = srv.accept()
        if not client: break
        thr = threading.Thread(None, lambda: commandloop(BufSock(client)))
        thr.run()
    srv.close()

def startup():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((control_host,control_port))
    c = TorCtl.get_connection(s)
    c.debug(file("control.log", "w"))
    c.authenticate()
    c.set_event_handler(SnakeHandler(c))
    c.set_events([TorCtl.EVENT_TYPE.STREAM,
                  TorCtl.EVENT_TYPE.NS,
                  TorCtl.EVENT_TYPE.CIRC,
                  TorCtl.EVENT_TYPE.NEWDESC], True)
    c.set_option("__LeaveStreamsUnattached", "1")
    return c

def main(argv):
    listenloop(startup())

if __name__ == '__main__':
    main(sys.argv)
