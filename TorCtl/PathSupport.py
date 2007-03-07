#!/usr/bin/python

import TorCtl
import re
import struct
import random
import socket
import copy
import datetime
import Queue
from TorUtil import *

__all__ = ["NodeRestrictionList", "PathRestrictionList",
"PercentileRestriction", "OSRestriction", "ConserveExitsRestriction",
"FlagsRestriction", "MinBWRestriction", "VersionIncludeRestriction",
"VersionExcludeRestriction", "ExitPolicyRestriction", "OrNodeRestriction",
"AtLeastNNodeRestriction", "NotNodeRestriction", "Subnet16Restriction",
"UniqueRestriction", "UniformGenerator", "OrderedExitGenerator",
"PathSelector", "Connection", "NickRestriction", "IdHexRestriction",
"PathBuilder", "SelectionManager"]

#################### Path Support Interfaces #####################

class NodeRestriction:
    "Interface for node restriction policies"
    def r_is_ok(self, r): return True    
    def reset(self, router_list): pass

class NodeRestrictionList:
    def __init__(self, restrictions, sorted_rlist):
        self.restrictions = restrictions
        self.update_routers(sorted_rlist)

    def __check_r(self, r):
        for rst in self.restrictions:
            if not rst.r_is_ok(r): return False
        self.restricted_bw += r.bw
        return True

    def update_routers(self, sorted_rlist):
        self._sorted_r = sorted_rlist
        self.restricted_bw = 0
        for rs in self.restrictions: rs.reset(sorted_rlist)
        self.restricted_r = filter(self.__check_r, self._sorted_r)

    def add_restriction(self, restr):
        self.restrictions.append(restr)
        for r in self.restricted_r:
            if not restr.r_is_ok(r):
                self.restricted_r.remove(r)
                self.restricted_bw -= r.bw
    
    # XXX: This does not collapse meta restrictions..
    def del_restriction(self, RestrictionClass):
        self.restrictions = filter(
                lambda r: not isinstance(r, RestrictionClass),
                    self.restrictions)
        self.update_routers(self._sorted_r)

class PathRestriction:
    "Interface for path restriction policies"
    def r_is_ok(self, path, r): return True    
    def entry_is_ok(self, path, r): return self.r_is_ok(path, r)
    def middle_is_ok(self, path, r): return self.r_is_ok(path, r)
    def exit_is_ok(self, path, r): return self.r_is_ok(path, r)

class PathRestrictionList:
    def __init__(self, restrictions):
        self.restrictions = restrictions
    
    def entry_is_ok(self, path, r):
        for rs in self.restrictions:
            if not rs.entry_is_ok(path, r):
                return False
        return True

    def middle_is_ok(self, path, r):
        for rs in self.restrictions:
            if not rs.middle_is_ok(path, r):
                return False
        return True

    def exit_is_ok(self, path, r):
        for rs in self.restrictions:
            if not rs.exit_is_ok(path, r):
                return False
        return True

    def add_restriction(self, rstr):
        self.restrictions.append(rstr)

    def del_restriction(self, RestrictionClass):
        self.restrictions = filter(
                lambda r: not isinstance(r, RestrictionClass),
                    self.restrictions)

class NodeGenerator:
    "Interface for node generation"
    def __init__(self, restriction_list):
        self.restriction_list = restriction_list
        self.rewind()

    def rewind(self):
        # TODO: Hrmm... Is there any way to handle termination other 
        # than to make a list of routers that we pop from? Random generators 
        # will not terminate if no node matches the selector without this..
        # Not so much an issue now, but in a few years, the Tor network
        # will be large enough that having all these list copies will
        # be obscene... Possible candidate for a python list comprehension
        self.routers = copy.copy(self.restriction_list.restricted_r)
        self.bw = self.restriction_list.restricted_bw

    def mark_chosen(self, r):
        self.routers.remove(r)
        self.bw -= r.bw

    def all_chosen(self):
        if not self.routers and self.bw or not self.bw and self.routers:
            plog("WARN", str(len(self.routers))+" routers left but bw="
                 +str(self.bw))
        return not self.routers

    def next_r(self): raise NotImplemented()

class Connection(TorCtl.Connection):
    def build_circuit(self, pathlen, path_sel):
        circ = TorCtl.Circuit()
        if pathlen == 1:
            circ.exit = path_sel.exit_chooser(circ.path)
            circ.path = [circ.exit]
            circ.cid = self.extend_circuit(0, circ.id_path())
        else:
            circ.path.append(path_sel.entry_chooser(circ.path))
            for i in xrange(1, pathlen-1):
                circ.path.append(path_sel.middle_chooser(circ.path))
            circ.exit = path_sel.exit_chooser(circ.path)
            circ.path.append(circ.exit)
            circ.cid = self.extend_circuit(0, circ.id_path())
        circ.created_at = datetime.datetime.now()
        return circ

######################## Node Restrictions ########################

# TODO: We still need more path support implementations
#  - BwWeightedGenerator
#  - NodeRestrictions:
#    - Uptime/LongLivedPorts (Does/should hibernation count?)
#    - Published/Updated
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
#      - EchelonPhobicRestrictor
#        - Does not cross international boundaries for client->Entry or
#          Exit->destination hops

class PercentileRestriction(NodeRestriction):
    """If used, this restriction MUST be FIRST in the RestrictionList."""
    def __init__(self, pct_skip, pct_fast, r_list):
        self.pct_fast = pct_fast
        self.pct_skip = pct_skip
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
            plog("WARN", "Router"+r.nickname+" at mismatched index: "
                         +self.position+" vs "+self.sorted_r.index(r))
        
        if self.position < len(self.sorted_r)*self.pct_skip/100:
            ret = False
        elif self.position > len(self.sorted_r)*self.pct_fast/100:
            ret = False
        
        self.position += 1
        return ret
        
class OSRestriction(NodeRestriction):
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

class ConserveExitsRestriction(NodeRestriction):
    def r_is_ok(self, r): return not "Exit" in r.flags

class FlagsRestriction(NodeRestriction):
    def __init__(self, mandatory, forbidden=[]):
        self.mandatory = mandatory
        self.forbidden = forbidden

    def r_is_ok(self, router):
        for m in self.mandatory:
            if not m in router.flags: return False
        for f in self.forbidden:
            if f in router.flags: return False
        return True

class NickRestriction(NodeRestriction):
    """Require that the node nickname is as specified"""
    def __init__(self, nickname):
        self.nickname = nickname

    def r_is_ok(self, router):
        return router.nickname == self.nickname

class IdHexRestriction(NodeRestriction):
    """Require that the node idhash is as specified"""
    def __init__(self, idhex):
        if idhex[0] == '$':
            self.idhex = idhex[1:].upper()
        else:
            self.idhex = idhex.upper()

    def r_is_ok(self, router):
        return router.idhex.upper() == self.idhex
    
class MinBWRestriction(NodeRestriction):
    def __init__(self, minbw):
        self.min_bw = minbw

    def r_is_ok(self, router): return router.bw >= self.min_bw
     
class VersionIncludeRestriction(NodeRestriction):
    def __init__(self, eq):
        self.eq = map(TorCtl.RouterVersion, eq)
    
    def r_is_ok(self, router):
        for e in self.eq:
            if e == router.version:
                return True
        return False


class VersionExcludeRestriction(NodeRestriction):
    def __init__(self, exclude):
        self.exclude = map(TorCtl.RouterVersion, exclude)
    
    def r_is_ok(self, router):
        for e in self.exclude:
            if e == router.version:
                return False
        return True

class VersionRangeRestriction(NodeRestriction):
    def __init__(self, gr_eq, less_eq=None):
        self.gr_eq = TorCtl.RouterVersion(gr_eq)
        if less_eq: self.less_eq = TorCtl.RouterVersion(less_eq)
        else: self.less_eq = None
    

    def r_is_ok(self, router):
        return (not self.gr_eq or router.version >= self.gr_eq) and \
                (not self.less_eq or router.version <= self.less_eq)

class ExitPolicyRestriction(NodeRestriction):
    def __init__(self, to_ip, to_port):
        self.to_ip = to_ip
        self.to_port = to_port

    def r_is_ok(self, r): return r.will_exit_to(self.to_ip, self.to_port)

class MetaNodeRestriction(NodeRestriction):
    # XXX: these should collapse the restriction and return a new
    # instance for re-insertion (or None)
    def next_rstr(self): raise NotImplemented()
    def del_restriction(self, RestrictionClass): raise NotImplemented()

class OrNodeRestriction(MetaNodeRestriction):
    def __init__(self, rs):
        self.rstrs = rs

    def r_is_ok(self, r):
        for rs in self.rstrs:
            if rs.r_is_ok(r):
                return True
        return False

class NotNodeRestriction(MetaNodeRestriction):
    def __init__(self, a):
        self.a = a

    def r_is_ok(self, r): return not self.a.r_is_ok(r)

class AtLeastNNodeRestriction(MetaNodeRestriction):
    def __init__(self, rstrs, n):
        self.rstrs = rstrs
        self.n = n

    def r_is_ok(self, r):
        cnt = 0
        for rs in self.rstrs:
            if rs.r_is_ok(r):
                cnt += 1
        if cnt < self.n: return False
        else: return True


#################### Path Restrictions #####################

class Subnet16Restriction(PathRestriction):
    def r_is_ok(self, path, router):
        mask16 = struct.unpack(">I", socket.inet_aton("255.255.0.0"))[0]
        ip16 = router.ip & mask16
        for r in path:
            if ip16 == (r.ip & mask16):
                return False
        return True

class UniqueRestriction(PathRestriction):
    def r_is_ok(self, path, r): return not r in path


#################### Node Generators ######################

class UniformGenerator(NodeGenerator):
    def next_r(self):
        while not self.all_chosen():
            r = random.choice(self.routers)
            self.mark_chosen(r)
            yield r

class OrderedExitGenerator(NodeGenerator):
    def __init__(self, restriction_list, to_port):
        self.to_port = to_port
        self.next_exit_by_port = {}
        NodeGenerator.__init__(self, restriction_list)

    def rewind(self):
        NodeGenerator.rewind(self)
        if self.to_port not in self.next_exit_by_port or not self.next_exit_by_port[self.to_port]:
            self.next_exit_by_port[self.to_port] = 0
            self.last_idx = len(self.routers)
        else:
            self.last_idx = self.next_exit_by_port[self.to_port]

    def set_port(self, port):
        self.to_port = port
        self.rewind()
       
    # Just in case: 
    def mark_chosen(self, r): raise NotImplemented()
    def all_chosen(self): raise NotImplemented()

    def next_r(self):
        while True: # A do..while would be real nice here..
            if self.next_exit_by_port[self.to_port] >= len(self.routers):
                self.next_exit_by_port[self.to_port] = 0
            r = self.routers[self.next_exit_by_port[self.to_port]]
            self.next_exit_by_port[self.to_port] += 1
            yield r
            if self.last_idx == self.next_exit_by_port[self.to_port]:
                break

####################### Secret Sauce ###########################

class PathError(Exception):
    pass

class NoRouters(PathError):
    pass

class PathSelector:
    "Implementation of path selection policies"
    def __init__(self, entry_gen, mid_gen, exit_gen, path_restrict):
        self.entry_gen = entry_gen
        self.mid_gen = mid_gen
        self.exit_gen = exit_gen
        self.path_restrict = path_restrict

    def entry_chooser(self, path):
        self.entry_gen.rewind()
        for r in self.entry_gen.next_r():
            if self.path_restrict.entry_is_ok(path, r):
                return r
        raise NoRouters();
        
    def middle_chooser(self, path):
        self.mid_gen.rewind()
        for r in self.mid_gen.next_r():
            if self.path_restrict.middle_is_ok(path, r):
                return r
        raise NoRouters();

    def exit_chooser(self, path):
        self.exit_gen.rewind()
        for r in self.exit_gen.next_r():
            if self.path_restrict.exit_is_ok(path, r):
                return r
        raise NoRouters();

class SelectionManager:
    """Helper class to handle configuration updates
      
      The methods are NOT threadsafe. They may ONLY be called from
      EventHandler's thread.

      To update the selection manager, schedule a config update job
      using PathBuilder.schedule_selmgr() with a worker function
      to modify this object.
      """
    def __init__(self, pathlen, order_exits,
                 percent_fast, percent_skip, min_bw, use_all_exits,
                 uniform, use_exit, use_guards):
        self.__ordered_exit_gen = None 
        self.pathlen = pathlen
        self.order_exits = order_exits
        self.percent_fast = percent_fast
        self.percent_skip = percent_skip
        self.min_bw = min_bw
        self.use_all_exits = use_all_exits
        self.uniform = uniform
        self.exit_name = use_exit
        self.use_guards = use_guards

    def reconfigure(self, sorted_r):
        if self.use_all_exits:
            self.path_rstr = PathRestrictionList([])
        else:
            self.path_rstr = PathRestrictionList(
                     [Subnet16Restriction(), UniqueRestriction()])
            
        self.entry_rstr = NodeRestrictionList(
            [
             PercentileRestriction(self.percent_skip, self.percent_fast,
                sorted_r),
             ConserveExitsRestriction(),
             FlagsRestriction(["Guard", "Valid", "Running"], [])
             ], sorted_r)
        self.mid_rstr = NodeRestrictionList(
            [PercentileRestriction(self.percent_skip, self.percent_fast,
                sorted_r),
             ConserveExitsRestriction(),
             FlagsRestriction(["Valid", "Running"], [])], sorted_r)

        if self.use_all_exits:
            self.exit_rstr = NodeRestrictionList(
                [FlagsRestriction(["Valid", "Running"], ["BadExit"])], sorted_r)
        else:
            self.exit_rstr = NodeRestrictionList(
                [PercentileRestriction(self.percent_skip, self.percent_fast,
                   sorted_r),
                 FlagsRestriction(["Valid", "Running"], ["BadExit"])],
                 sorted_r)

        if self.exit_name:
            if self.exit_name[0] == '$':
                self.exit_rstr.add_restriction(IdHexRestriction(self.exit_name))
            else:
                self.exit_rstr.add_restriction(NickRestriction(self.exit_name))

        # This is kind of hokey..
        if self.order_exits:
            if self.__ordered_exit_gen:
                exitgen = self.__ordered_exit_gen
            else:
                exitgen = self.__ordered_exit_gen = \
                    OrderedExitGenerator(self.exit_rstr, 80)
        else:
            exitgen = UniformGenerator(self.exit_rstr)

        if self.uniform:
            self.path_selector = PathSelector(
                 UniformGenerator(self.entry_rstr),
                 UniformGenerator(self.mid_rstr),
                 exitgen, self.path_rstr)
        else:
            raise NotImplemented()

    def set_target(self, ip, port):
        self.exit_rstr.del_restriction(ExitPolicyRestriction)
        self.exit_rstr.add_restriction(ExitPolicyRestriction(ip, port))
        if self.__ordered_exit_gen: self.__ordered_exit_gen.set_port(port)

    def update_routers(self, new_rlist):
        self.entry_rstr.update_routers(new_rlist)
        self.mid_rstr.update_routers(new_rlist)
        self.exit_rstr.update_routers(new_rlist)

class Circuit(TorCtl.Circuit):
    def __init__(self, circuit): # Promotion constructor
        # perf shortcut since we don't care about the 'circuit' 
        # instance after this
        self.__dict__ = circuit.__dict__
        self.built = False
        self.detached_cnt = 0
        self.created_at = datetime.datetime.now()
        self.pending_streams = [] # Which stream IDs are pending us

class Stream:
    def __init__(self, sid, host, port, kind):
        self.sid = sid
        self.detached_from = [] # circ id #'s
        self.pending_circ = None
        self.circ = None
        self.host = host
        self.port = port
        self.kind = kind

# TODO: Make passive "PathWatcher" so people can get aggregate 
# node reliability stats for normal usage without us attaching streams

class PathBuilder(TorCtl.EventHandler):
    """
    PathBuilder implementation. Handles circuit construction, subject
    to the constraints of the SelectionManager selmgr.
    
    Do not access this object from other threads. Instead, use the 
    schedule_* functions to schedule work to be done in the thread
    of the EventHandler.
    """
    def __init__(self, c, selmgr, RouterClass):
        TorCtl.EventHandler.__init__(self)
        self.c = c
        nslist = c.get_network_status()
        self.last_exit = None
        self.new_nym = False
        self.resolve_port = 0
        self.num_circuits = 1
        self.RouterClass = RouterClass
        self.sorted_r = []
        self.routers = {}
        self.circuits = {}
        self.streams = {}
        self.read_routers(nslist)
        self.selmgr = selmgr
        self.selmgr.reconfigure(self.sorted_r)
        self.imm_jobs = Queue.Queue()
        self.low_prio_jobs = Queue.Queue()
        self.do_reconfigure = False
        plog("INFO", "Read "+str(len(self.sorted_r))+"/"+str(len(nslist))+" routers")

    def read_routers(self, nslist):
        routers = self.c.read_routers(nslist)
        new_routers = []
        for r in routers:
            if r.idhex in self.routers:
                if self.routers[r.idhex].nickname != r.nickname:
                    plog("NOTICE", "Router "+r.idhex+" changed names from "
                         +self.routers[r.idhex].nickname+" to "+r.nickname)
                # Must do IN-PLACE update to keep all the refs to this router
                # valid and current (especially for stats)
                self.routers[r.idhex].update_to(r)
            else:
                self.routers[r.idhex] = self.RouterClass(r)
                new_routers.append(self.RouterClass(r))
        self.sorted_r.extend(new_routers)
        self.sorted_r.sort(lambda x, y: cmp(y.bw, x.bw))

    def attach_stream_any(self, stream, badcircs):
        # Newnym, and warn if not built plus pending
        unattached_streams = [stream]
        if self.new_nym:
            self.new_nym = False
            plog("DEBUG", "Obeying new nym")
            for key in self.circuits.keys():
                if len(self.circuits[key].pending_streams):
                    plog("WARN", "New nym called, destroying circuit "+str(key)
                         +" with "+str(len(self.circuits[key].pending_streams))
                         +" pending streams")
                    unattached_streams.extend(self.circuits[key].pending_streams)
                # FIXME: Consider actually closing circ if no streams.
                del self.circuits[key]
            
        for circ in self.circuits.itervalues():
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
                self.selmgr.set_target(stream.host, stream.port)
                try:
                    circ = Circuit(self.c.build_circuit(
                                    self.selmgr.pathlen,
                                    self.selmgr.path_selector))
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
            self.circuits[circ.cid] = circ
        self.last_exit = circ.exit


    def schedule_immediate(self, job):
        """
        Schedules an immediate job to be run before the next event is
        processed.
        """
        self.imm_jobs.put(job)

    def schedule_low_prio(self, job):
        """
        Schedules a job to be run when a non-time critical event arrives.
        """
        self.low_prio_jobs.put(job)

    def schedule_selmgr(self, job):
        """
        Schedules an immediate job to be run before the next event is
        processed. Also notifies the selection manager that it needs
        to update itself.
        """
        def notlambda(this):
            job(this.selmgr)
            this.do_reconfigure = True
        self.schedule_immediate(notlambda)

    def heartbeat_event(self, event):
        while not self.imm_jobs.empty():
            imm_job = self.imm_jobs.get_nowait()
            imm_job(self)
        
        if self.do_reconfigure:
            self.selmgr.reconfigure(self.sorted_r)
            self.do_reconfigure = False
        
        # If event is stream:NEW*/DETACHED or circ BUILT/FAILED, 
        # don't run low prio jobs.. No need to delay streams on them.
        if isinstance(event, TorCtl.CircuitEvent):
            if event.status in ("BUILT", "FAILED"): return
        elif isinstance(event, TorCtl.StreamEvent):
            if event.status in ("NEW", "NEWRESOLVE", "DETACHED"): return
        
        # Do the low prio jobs one at a time in case a 
        # higher priority event is queued   
        if not self.low_prio_jobs.empty():
            delay_job = self.low_prio_jobs.get_nowait()
            delay_job(self)

    def circ_status_event(self, c):
        output = [c.event_name, str(c.circ_id), c.status]
        if c.path: output.append(",".join(c.path))
        if c.reason: output.append("REASON=" + c.reason)
        if c.remote_reason: output.append("REMOTE_REASON=" + c.remote_reason)
        plog("DEBUG", " ".join(output))
        # Circuits we don't control get built by Tor
        if c.circ_id not in self.circuits:
            plog("DEBUG", "Ignoring circ " + str(c.circ_id))
            return
        if c.status == "FAILED" or c.status == "CLOSED":
            circ = self.circuits[c.circ_id]
            del self.circuits[c.circ_id]
            for stream in circ.pending_streams:
                plog("DEBUG", "Finding new circ for " + str(stream.sid))
                self.attach_stream_any(stream, stream.detached_from)
        elif c.status == "BUILT":
            self.circuits[c.circ_id].built = True
            for stream in self.circuits[c.circ_id].pending_streams:
                self.c.attach_stream(stream.sid, c.circ_id)

    def stream_status_event(self, s):
        output = [s.event_name, str(s.strm_id), s.status, str(s.circ_id),
                  s.target_host, str(s.target_port)]
        if s.reason: output.append("REASON=" + s.reason)
        if s.remote_reason: output.append("REMOTE_REASON=" + s.remote_reason)
        plog("DEBUG", " ".join(output))
        if not re.match(r"\d+.\d+.\d+.\d+", s.target_host):
            s.target_host = "255.255.255.255" # ignore DNS for exit policy check
        if s.status == "NEW" or s.status == "NEWRESOLVE":
            if s.status == "NEWRESOLVE" and not s.target_port:
                s.target_port = self.resolve_port
            self.streams[s.strm_id] = Stream(s.strm_id, s.target_host, s.target_port, s.status)

            self.attach_stream_any(self.streams[s.strm_id],
                                   self.streams[s.strm_id].detached_from)
        elif s.status == "DETACHED":
            if s.strm_id not in self.streams:
                plog("WARN", "Detached stream "+str(s.strm_id)+" not found")
                self.streams[s.strm_id] = Stream(s.strm_id, s.target_host,
                                            s.target_port, "NEW")
            # FIXME Stats (differentiate Resolved streams also..)
            if not s.circ_id:
                plog("WARN", "Stream "+str(s.strm_id)+" detached from no circuit!")
            else:
                self.streams[s.strm_id].detached_from.append(s.circ_id)

            
            if self.streams[s.strm_id] in self.streams[s.strm_id].pending_circ.pending_streams:
                self.streams[s.strm_id].pending_circ.pending_streams.remove(self.streams[s.strm_id])
            self.streams[s.strm_id].pending_circ = None
            self.attach_stream_any(self.streams[s.strm_id],
                                   self.streams[s.strm_id].detached_from)
        elif s.status == "SUCCEEDED":
            if s.strm_id not in self.streams:
                plog("NOTICE", "Succeeded stream "+str(s.strm_id)+" not found")
                return
            self.streams[s.strm_id].circ = self.streams[s.strm_id].pending_circ
            self.streams[s.strm_id].circ.pending_streams.remove(self.streams[s.strm_id])
            self.streams[s.strm_id].pending_circ = None
        elif s.status == "FAILED" or s.status == "CLOSED":
            # FIXME stats
            if s.strm_id not in self.streams:
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
                if s.circ_id in self.circuits: del self.circuits[s.circ_id]
                else: plog("WARN","Failed stream on unknown circ "+str(s.circ_id))
                return

            if self.streams[s.strm_id].pending_circ:
                self.streams[s.strm_id].pending_circ.pending_streams.remove(self.streams[s.strm_id])
            del self.streams[s.strm_id]
        elif s.status == "REMAP":
            if s.strm_id not in self.streams:
                plog("WARN", "Remap id "+str(s.strm_id)+" not found")
            else:
                if not re.match(r"\d+.\d+.\d+.\d+", s.target_host):
                    s.target_host = "255.255.255.255"
                    plog("NOTICE", "Non-IP remap for "+str(s.strm_id)+" to "
                                   + s.target_host)
                self.streams[s.strm_id].host = s.target_host
                self.streams[s.strm_id].port = s.target_port


    def ns_event(self, n):
        self.read_routers(n.nslist)
        plog("DEBUG", "Read " + str(len(n.nslist))+" NS => " 
             + str(len(self.sorted_r)) + " routers")
        self.selmgr.update_routers(self.sorted_r)
    
    def new_desc_event(self, d):
        for i in d.idlist: # Is this too slow?
            self.read_routers(self.c.get_network_status("id/"+i))
        plog("DEBUG", "Read " + str(len(d.idlist))+" Desc => " 
             + str(len(self.sorted_r)) + " routers")
        self.selmgr.update_routers(self.sorted_r)

########################## Unit tests ##########################


def do_unit(rst, r_list, plamb):
    print "\n"
    print "-----------------------------------"
    print rst.r_is_ok.im_class
    for r in r_list:
        print r.nickname+" "+plamb(r)+"="+str(rst.r_is_ok(r))

# TODO: Tests:
#  - Test each NodeRestriction and print in/out lines for it
#  - Test NodeGenerator and reapply NodeRestrictions
#  - Same for PathSelector and PathRestrictions
#    - Also Reapply each restriction by hand to path. Verify returns true

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1",9061))
    c = Connection(s)
    c.debug(file("control.log", "w"))
    c.authenticate()
    nslist = c.get_network_status()
    sorted_rlist = c.read_routers(c.get_network_status())
    
    for r in sorted_rlist:
        if r.will_exit_to("211.11.21.22", 465):
            print r.nickname+" "+str(r.bw)

    do_unit(PercentileRestriction(0, 100, sorted_rlist), sorted_rlist,
                  lambda r: "")
    do_unit(PercentileRestriction(10, 20, sorted_rlist), sorted_rlist,
                  lambda r: "")
    do_unit(OSRestriction([r"[lL]inux", r"BSD", "Darwin"], []), sorted_rlist,
                  lambda r: r.os)
    do_unit(OSRestriction([], ["Windows", "Solaris"]), sorted_rlist,
                  lambda r: r.os)
   
    do_unit(VersionRangeRestriction("0.1.2.0"), sorted_rlist,
                  lambda r: str(r.version))
    do_unit(VersionRangeRestriction("0.1.2.0", "0.1.2.5"), sorted_rlist,
                  lambda r: str(r.version))
    do_unit(VersionIncludeRestriction(["0.1.1.26-alpha", "0.1.2.7-ignored"]),
                  sorted_rlist, lambda r: str(r.version))
    do_unit(VersionExcludeRestriction(["0.1.1.26"]), sorted_rlist,
                  lambda r: str(r.version))

    do_unit(ConserveExitsRestriction(), sorted_rlist, lambda r: " ".join(r.flags))
    do_unit(FlagsRestriction([], ["Valid"]), sorted_rlist, lambda r: " ".join(r.flags))

    # XXX: Need unittest
    do_unit(IdHexRestriction("$FFCB46DB1339DA84674C70D7CB586434C4370441"),
                  sorted_rlist, lambda r: r.idhex)

    rl =  [AtLeastNNodeRestriction([ExitPolicyRestriction("255.255.255.255", 80), ExitPolicyRestriction("255.255.255.255", 443), ExitPolicyRestriction("255.255.255.255", 6667)], 2), FlagsRestriction([], ["BadExit"])]

    exit_rstr = NodeRestrictionList(rl, sorted_rlist)

    ug = UniformGenerator(exit_rstr)

    rlist = []
    for r in ug.next_r():
        print "Checking: " + r.nickname
        for rs in rl:
            if not rs.r_is_ok(r):
                raise PathError()
            if not "Exit" in r.flags:
                print "No exit in flags of "+r.nickname
        rlist.append(r)
    for r in sorted_rlist:
        if "Exit" in r.flags and not r in rlist:
            print r.nickname+" is an exit not in rl!"
                
