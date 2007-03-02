#!/usr/bin/python

import TorCtl
import re
import struct
import random
import socket
import copy
import datetime
from TorUtil import *

__all__ = ["NodeRestrictionList", "PathRestrictionList",
"PercentileRestriction", "OSRestriction", "ConserveExitsRestriction",
"FlagsRestriction", "MinBWRestriction", "VersionIncludeRestriction",
"VersionExcludeRestriction", "ExitPolicyRestriction", "OrNodeRestriction",
"AtLeastNNodeRestriction", "NotNodeRestriction", "Subnet16Restriction",
"UniqueRestriction", "UniformGenerator", "OrderedExitGenerator",
"PathSelector", "Connection", "NickRestriction", "IdHexRestriction"]

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

    do_unit(PercentileRestriction(0, 100, sorted_rlist), sorted_rlist,
                  lambda r: "")
    do_unit(PercentileRestriction(10, 20, sorted_rlist), sorted_rlist,
                  lambda r: "")
    exit(0)
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
                raise PathException()
            if not "Exit" in r.flags:
                print "No exit in flags of "+r.nickname
        rlist.append(r)
    for r in sorted_r:
        if "Exit" in r.flags and not r in rlist:
            print r.nickname+" is an exit not in rl!"
                
