#!/usr/bin/python
# TorCtl.py -- Python module to interface with Tor Control interface.
# Copyright 2005 Nick Mathewson -- See LICENSE for licensing information.
#$Id: TorCtl.py 6882 2005-11-19 19:42:31Z nickm $

"""
TorCtl -- Library to control Tor processes.  See TorCtlDemo.py for example use.
"""

import os
import re
import struct
import sys
import threading
import Queue
import datetime
import traceback
import socket
import binascii
import types

# XXX: Make a TorUtil.py
class _Enum:
    # Helper: define an ordered dense name-to-number 1-1 mapping.
    def __init__(self, start, names):
        self.nameOf = {}
        idx = start
        for name in names:
            setattr(self,name,idx)
            self.nameOf[idx] = name
            idx += 1

class _Enum2:
    # Helper: define an ordered sparse name-to-number 1-1 mapping.
    def __init__(self, **args):
        self.__dict__.update(args)
        self.nameOf = {}
        for k,v in args.items():
            self.nameOf[v] = k

def _quote(s):
    return re.sub(r'([\r\n\\\"])', r'\\\1', s)

def _escape_dots(s, translate_nl=1):
    if translate_nl:
        lines = re.split(r"\r?\n", s)
    else:
        lines = s.split("\r\n")
    if lines and not lines[-1]:
        del lines[-1]
    for i in xrange(len(lines)):
        if lines[i].startswith("."):
            lines[i] = "."+lines[i]
    lines.append(".\r\n")
    return "\r\n".join(lines)

def _unescape_dots(s, translate_nl=1):
    lines = s.split("\r\n")

    for i in xrange(len(lines)):
        if lines[i].startswith("."):
            lines[i] = lines[i][1:]

    if lines and lines[-1]:
        lines.append("")

    if translate_nl:
        return "\n".join(lines)
    else:
        return "\r\n".join(lines)

class _BufSock:
    def __init__(self, s):
        self._s = s
        self._buf = []

    def readline(self):
        if self._buf:
            idx = self._buf[0].find('\n')
            if idx >= 0:
                result = self._buf[0][:idx+1]
                self._buf[0] = self._buf[0][idx+1:]
                return result

        while 1:
            s = self._s.recv(128)
            if not s:
                raise TorCtlClosed()
            idx = s.find('\n')
            if idx >= 0:
                self._buf.append(s[:idx+1])
                result = "".join(self._buf)
                rest = s[idx+1:]
                if rest:
                    self._buf = [ rest ]
                else:
                    del self._buf[:]
                return result
            else:
                self._buf.append(s)

    def write(self, s):
        self._s.send(s)

    def close(self):
        self._s.close()

def secret_to_key(secret, s2k_specifier):
    """Used to generate a hashed password string. DOCDOC."""
    c = ord(s2k_specifier[8])
    EXPBIAS = 6
    count = (16+(c&15)) << ((c>>4) + EXPBIAS)

    d = sha.new()
    tmp = s2k_specifier[:8]+secret
    slen = len(tmp)
    while count:
        if count > slen:
            d.update(tmp)
            count -= slen
        else:
            d.update(tmp[:count])
            count = 0
    return d.digest()

def urandom_rng(n):
    """Try to read some entropy from the platform entropy source."""
    f = open('/dev/urandom', 'rb')
    try:
        return f.read(n)
    finally:
        f.close()

def s2k_gen(secret, rng=None):
    """DOCDOC"""
    if rng is None:
        if hasattr(os, "urandom"):
            rng = os.urandom
        else:
            rng = urandom_rng
    spec = "%s%s"%(rng(8), chr(96))
    return "16:%s"%(
        binascii.b2a_hex(spec + secret_to_key(secret, spec)))

def s2k_check(secret, k):
    """DOCDOC"""
    assert k[:3] == "16:"

    k =  binascii.a2b_hex(k[3:])
    return secret_to_key(secret, k[:9]) == k[9:]

# Types of "EVENT" message.
EVENT_TYPE = _Enum2(
                    CIRC="CIRC",
                    STREAM="STREAM",
                    ORCONN="ORCONN",
                    BW="BW",
                    NS="NS",
                    NEWDESC="NEWDESC",
                    DEBUG="DEBUG",
                    INFO="INFO",
                    NOTICE="NOTICE",
                    WARN="WARN",
                    ERR="ERR")

loglevel = "DEBUG"
loglevels = {"DEBUG" : 0, "INFO" : 1, "NOTICE" : 2, "WARN" : 3, "ERROR" : 4}

def plog(level, msg): # XXX: Timestamps
    if(loglevels[level] >= loglevels[loglevel]):
        print level + ": " + msg

class TorCtlError(Exception):
    "Generic error raised by TorControl code."
    pass

class TorCtlClosed(TorCtlError):
    "Raised when the controller connection is closed by Tor (not by us.)"
    pass

class ProtocolError(TorCtlError):
    "Raised on violations in Tor controller protocol"
    pass

class ErrorReply(TorCtlError):
    "Raised when Tor controller returns an error"
    pass

class NetworkStatus:
    "Filled in during NS events"
    pass

class ExitPolicyLine:
    def __init__(self, match, ip_mask, port_low, port_high):
        self.match = match
        if ip_mask == "*":
            self.ip = 0
            self.netmask = 0
        else:
            if ip_mask.find("/") == -1:
                self.netmask = 0xFFFFFFFF
                ip = ip_mask
            else:
                ip, mask = ip_mask.split("/")
                if re.match(r"\d+.\d+.\d+.\d+", mask):
                    self.netmask=struct.unpack(">I", socket.inet_aton(mask))[0]
                else:
                    self.netmask = ~(2**(32 - int(mask)) - 1)
            self.ip = struct.unpack(">I", socket.inet_aton(ip))[0]
        self.ip &= self.netmask
        if port_low == "*":
            self.port_low,self.port_high = (0,65535)
        else:
            if not port_high:
                port_high = port_low
            self.port_low = int(port_low)
            self.port_high = int(port_high)
    
    def check(self, ip, port):
        ip = struct.unpack(">I", socket.inet_aton(ip))[0]
        if (ip & self.netmask) == self.ip:
            if self.port_low <= port and port <= self.port_high:
                return self.match
        return -1

# XXX: Parse out version and OS
class Router:
    def __init__(self, idhex, name, bw, exitpolicy, down, guard, valid,
                 badexit, fast):
        self.idhex = idhex
        self.name = name
        self.bw = bw
        self.exitpolicy = exitpolicy
        self.guard = guard
        self.down = down
        self.badexit = badexit
        self.valid = valid
        self.fast = fast

    def will_exit_to(self, ip, port):
        for line in self.exitpolicy:
            ret = line.check(ip, port)
            if ret != -1:
                if ret: plog("DEBUG", "Match: "+str(ret)+" for "+self.name)
                return ret
        plog("NOTICE", "No matching exit line for "+self.name)
        return 0

class Circuit:
    def __init__(self):
        self.cid = 0
        self.created_at = 0 # time
        self.path = [] # routers
        self.exit = 0


class _ConnectionBase:
    def __init__(self):
        self._s = None
        self._handler = None
        self._handleFn = None
        self._sendLock = threading.RLock()
        self._queue = Queue.Queue()
        self._thread = None
        self._closedEx = None
        self._closed = 0
        self._closeHandler = None
        self._eventThread = None
        self._eventQueue = Queue.Queue()

    def set_event_handler(self, handler):
        """Cause future events from the Tor process to be sent to 'handler'.
        """
        raise NotImplemented

    def set_close_handler(self, handler):
        """Call 'handler' when the Tor process has closed its connection or
           given us an exception.  If we close normally, no arguments are
           provided; otherwise, it will be called with an exception as its
           argument.
        """
        self._closeHandler = handler

    def close(self):
        """Shut down this controller connection"""
        self._sendLock.acquire()
        try:
            self._queue.put("CLOSE")
            self._eventQueue.put("CLOSE")
            self._s.close()
            self._s = None
            self._closed = 1
        finally:
            self._sendLock.release()

#    def _read_reply(self):
#        """DOCDOC"""
#        raise NotImplementd

    def launch_thread(self, daemon=1):
        """Launch a background thread to handle messages from the Tor process."""
        assert self._thread is None
        t = threading.Thread(target=self._loop)
        if daemon:
            t.setDaemon(daemon)
        t.start()
        self._thread = t
        t = threading.Thread(target=self._eventLoop)
        if daemon:
            t.setDaemon(daemon)
        t.start()
        self._eventThread = t
        return self._thread

    def _loop(self):
        """Main subthread loop: Read commands from Tor, and handle them either
           as events or as responses to other commands.
        """
        while 1:
            ex = None
            try:
                isEvent, reply = self._read_reply()
            except:
                self._err(sys.exc_info())
                return

            if isEvent:
                if self._handler is not None:
                    self._eventQueue.put(reply)
            else:
                cb = self._queue.get()
                cb(reply)

    def _err(self, (tp, ex, tb), fromEventLoop=0):
        """DOCDOC"""
        # silent death is bad :(
        traceback.print_exception(tp, ex, tb)
        if self._s:
            try:
                self.close()
            except:
                pass
        self._sendLock.acquire()
        try:
            self._closedEx = ex
            self._closed = 1
        finally:
            self._sendLock.release()
        while 1:
            try:
                cb = self._queue.get(timeout=0)
                if cb != "CLOSE":
                    cb("EXCEPTION")
            except Queue.Empty:
                break
        if self._closeHandler is not None:
            self._closeHandler(ex)
        return

    def _eventLoop(self):
        """DOCDOC"""
        while 1:
            reply = self._eventQueue.get()
            if reply == "CLOSE":
                return
            try:
                self._handleFn(reply)
            except:
                self._err(sys.exc_info(), 1)
                return

    def _sendImpl(self, sendFn, msg):
        """DOCDOC"""
        if self._thread is None:
            self.launch_thread(1)
        # This condition will get notified when we've got a result...
        condition = threading.Condition()
        # Here's where the result goes...
        result = []

        if self._closedEx is not None:
            raise self._closedEx
        elif self._closed:
            raise TorCtlClosed()

        def cb(reply,condition=condition,result=result):
            condition.acquire()
            try:
                result.append(reply)
                condition.notify()
            finally:
                condition.release()

        # Sends a message to Tor...
        self._sendLock.acquire()
        try:
            self._queue.put(cb)
            sendFn(msg)
        finally:
            self._sendLock.release()

        # Now wait till the answer is in...
        condition.acquire()
        try:
            while not result:
                condition.wait()
        finally:
            condition.release()

        # ...And handle the answer appropriately.
        assert len(result) == 1
        reply = result[0]
        if reply == "EXCEPTION":
            raise self._closedEx

        return reply


class Connection(_ConnectionBase):
    """A Connection represents a connection to the Tor process."""
    def __init__(self, sock):
        """Create a Connection to communicate with the Tor process over the
           socket 'sock'.
        """
        _ConnectionBase.__init__(self)
        self._s = _BufSock(sock)
        self._debugFile = None

    def debug(self, f):
        """DOCDOC"""
        self._debugFile = f

    def set_event_handler(self, handler):
        """Cause future events from the Tor process to be sent to 'handler'.
        """
        self._handler = handler
        self._handleFn = handler.handle1

    def _read_reply(self):
        lines = []
        while 1:
            line = self._s.readline().strip()
            if self._debugFile:
                self._debugFile.write("    %s\n" % line)
            if len(line)<4:
                raise ProtocolError("Badly formatted reply line: Too short")
            code = line[:3]
            tp = line[3]
            s = line[4:]
            if tp == "-":
                lines.append((code, s, None))
            elif tp == " ":
                lines.append((code, s, None))
                isEvent = (lines and lines[0][0][0] == '6')
                return isEvent, lines
            elif tp != "+":
                raise ProtocolError("Badly formatted reply line: unknown type %r"%tp)
            else:
                more = []
                while 1:
                    line = self._s.readline()
                    if self._debugFile and tp != "+":
                        self._debugFile.write("    %s" % line)
                    if line in (".\r\n", ".\n"):
                        break
                    more.append(line)
                lines.append((code, s, _unescape_dots("".join(more))))
        isEvent = (lines and lines[0][0][0] == '6')
        return (isEvent, lines)

    def _doSend(self, msg):
        if self._debugFile:
            amsg = msg
            lines = amsg.split("\n")
            if len(lines) > 2:
                amsg = "\n".join(lines[:2]) + "\n"
            self._debugFile.write(">>> %s" % amsg)
        self._s.write(msg)

    def _sendAndRecv(self, msg="", expectedTypes=("250", "251")):
        """Helper: Send a command 'msg' to Tor, and wait for a command
           in response.  If the response type is in expectedTypes,
           return a list of (tp,body,extra) tuples.  If it is an
           error, raise ErrorReply.  Otherwise, raise ProtocolError.
        """
        if type(msg) == types.ListType:
            msg = "".join(msg)
        assert msg.endswith("\r\n")

        lines = self._sendImpl(self._doSend, msg)
        # print lines
        for tp, msg, _ in lines:
            if tp[0] in '45':
                raise ErrorReply("%s %s"%(tp, msg))
            if tp not in expectedTypes:
                raise ProtocolError("Unexpectd message type %r"%tp)

        return lines

    def authenticate(self, secret=""):
        """Send an authenticating secret to Tor.  You'll need to call this
           method before Tor can start.
        """
        hexstr = binascii.b2a_hex(secret)
        self._sendAndRecv("AUTHENTICATE %s\r\n"%hexstr)

    def get_option(self, name):
        """Get the value of the configuration option named 'name'.  To
           retrieve multiple values, pass a list for 'name' instead of
           a string.  Returns a list of (key,value) pairs.
           Refer to section 3.3 of control-spec.txt for a list of valid names.
        """
        if not isinstance(name, str):
            name = " ".join(name)
        lines = self._sendAndRecv("GETCONF %s\r\n" % name)

        r = []
        for _,line,_ in lines:
            try:
                key, val = line.split("=", 1)
                r.append((key,val))
            except ValueError:
                r.append((line, None))

        return r

    def set_option(self, key, value):
        """Set the value of the configuration option 'key' to the value 'value'.
        """
        self.set_options([(key, value)])

    def set_options(self, kvlist):
        """Given a list of (key,value) pairs, set them as configuration
           options.
        """
        if not kvlist:
            return
        msg = " ".join(["%s=%s"%(k,_quote(v)) for k,v in kvlist])
        self._sendAndRecv("SETCONF %s\r\n"%msg)

    def reset_options(self, keylist):
        """Reset the options listed in 'keylist' to their default values.

           Tor started implementing this command in version 0.1.1.7-alpha;
           previous versions wanted you to set configuration keys to "".
           That no longer works.
        """
        self._sendAndRecv("RESETCONF %s\r\n"%(" ".join(keylist)))

    def get_network_status(self, who="all"):
        """Get the entire network status list"""
        return parse_ns_body(self._sendAndRecv("GETINFO ns/"+who+"\r\n")[0][2])

    def get_router(self, ns):
        """Fill in a Router class corresponding to a given NS class"""
        desc = self._sendAndRecv("GETINFO desc/id/" + ns.idhex + "\r\n")[0][2].split("\n")
        line = desc.pop(0)
        m = re.search(r"^router\s+(\S+)\s+", line)
        router = m.group(1)
        exitpolicy = []
        dead = not ("Running" in ns.flags)
        bw_observed = 0
        if router != ns.name:
            plog("NOTICE", "Got different names " + ns.name + " vs " +
                         router + " for " + ns.idhex)
        for line in desc:
            ac = re.search(r"^accept (\S+):([^-]+)(?:-(\d+))?", line)
            rj = re.search(r"^reject (\S+):([^-]+)(?:-(\d+))?", line)
            bw = re.search(r"^bandwidth \d+ \d+ (\d+)", line)
            if re.search(r"^opt hibernating 1", line):
                dead = 1
            if ac:
                exitpolicy.append(ExitPolicyLine(1, *ac.groups()))
            elif rj:
                exitpolicy.append(ExitPolicyLine(0, *rj.groups()))
            elif bw:
                bw_observed = int(bw.group(1))
        if not bw_observed and not dead and ("Valid" in ns.flags):
            plog("NOTICE", "No bandwidth for live router " + ns.name)
        return Router(ns.idhex, ns.name, bw_observed, exitpolicy, dead,
                ("Guard" in ns.flags), ("Valid" in ns.flags),
                ("BadExit" in ns.flags), ("Fast" in ns.flags))

    def get_info(self, name):
        """Return the value of the internal information field named 'name'.
           Refer to section 3.9 of control-spec.txt for a list of valid names.
           DOCDOC
        """
        if not isinstance(name, str):
            name = " ".join(name)
        lines = self._sendAndRecv("GETINFO %s\r\n"%name)
        d = {}
        for _,msg,more in lines:
            if msg == "OK":
                break
            try:
                k,rest = msg.split("=",1)
            except ValueError:
                raise ProtocolError("Bad info line %r",msg)
            if more:
                d[k] = more
            else:
                d[k] = rest
        return d

    def set_events(self, events, extended=False):
        """Change the list of events that the event handler is interested
           in to those in 'events', which is a list of event names.
           Recognized event names are listed in section 3.3 of the control-spec
        """
        if extended:
            print ("SETEVENTS EXTENDED %s\r\n" % " ".join(events))
            self._sendAndRecv("SETEVENTS EXTENDED %s\r\n" % " ".join(events))
        else:
            self._sendAndRecv("SETEVENTS %s\r\n" % " ".join(events))

    def save_conf(self):
        """Flush all configuration changes to disk.
        """
        self._sendAndRecv("SAVECONF\r\n")

    def send_signal(self, sig):
        """Send the signal 'sig' to the Tor process; The allowed values for
           'sig' are listed in section 3.6 of control-spec.
        """
        sig = { 0x01 : "HUP",
                0x02 : "INT",
                0x0A : "USR1",
                0x0C : "USR2",
                0x0F : "TERM" }.get(sig,sig)
        self._sendAndRecv("SIGNAL %s\r\n"%sig)

    def map_address(self, kvList):
        if not kvList:
            return
        m = " ".join([ "%s=%s" for k,v in kvList])
        lines = self._sendAndRecv("MAPADDRESS %s\r\n"%m)
        r = []
        for _,line,_ in lines:
            try:
                key, val = line.split("=", 1)
            except ValueError:
                raise ProtocolError("Bad address line %r",v)
            r.append((key,val))
        return r

    def extend_circuit(self, circid, hops):
        """Tell Tor to extend the circuit identified by 'circid' through the
           servers named in the list 'hops'.
        """
        if circid is None:
            circid = "0"
        lines = self._sendAndRecv("EXTENDCIRCUIT %s %s\r\n"
                                  %(circid, ",".join(hops)))
        tp,msg,_ = lines[0]
        m = re.match(r'EXTENDED (\S*)', msg)
        if not m:
            raise ProtocolError("Bad extended line %r",msg)
        return int(m.group(1))

    def build_circuit(self, pathlen, entry_chooser, middle_chooser, exit_chooser):
        circ = Circuit()
        if pathlen == 1:
            circ.exit = exit_chooser(circ.path)
            circ.path = [circ.exit]
            circ.cid = self.extend_circuit(0, circ.path)
        else:
            circ.path.append(entry_chooser(circ.path))
            for i in xrange(1, pathlen-1):
                circ.path.append(middle_chooser(circ.path))
            circ.path.append(exit_chooser(circ.path))
            circ.cid = self.extend_circuit(0, circ.path)
        circ.created_at = datetime.datetime.now()
        return circ
 

    def redirect_stream(self, streamid, newaddr, newport=""):
        """DOCDOC"""
        if newport:
            self._sendAndRecv("REDIRECTSTREAM %s %s %s\r\n"%(streamid, newaddr, newport))
        else:
            self._sendAndRecv("REDIRECTSTREAM %s %s\r\n"%(streamid, newaddr))

    def attach_stream(self, streamid, circid):
        """DOCDOC"""
        self._sendAndRecv("ATTACHSTREAM %s %s\r\n"%(streamid, circid))

    def close_stream(self, streamid, reason=0, flags=()):
        """DOCDOC"""
        self._sendAndRecv("CLOSESTREAM %s %s %s\r\n"
                          %(streamid, reason, "".join(flags)))

    def close_circuit(self, circid, reason=0, flags=()):
        """DOCDOC"""
        self._sendAndRecv("CLOSECIRCUIT %s %s %s\r\n"
                          %(circid, reason, "".join(flags)))

    def post_descriptor(self, desc):
        self._sendAndRecv("+POSTDESCRIPTOR\r\n%s"%_escape_dots(desc))

def parse_ns_body(data):
    "Parse the body of an NS event or command."
    nsgroups = re.compile(r"^r ", re.M).split(data)
    nsgroups.pop(0)
    nslist = []
    for nsline in nsgroups:
        ns = NetworkStatus()
        m = re.match(r"(\S+)\s(\S+)\s(\S+)\s(\S+\s\S+)\s(\S+)\s(\d+)\s(\d+)", nsline)
        ns.name,ns.idhash,ns.orhash,updated,ns.ip,ns.orport,ns.dirport = m.groups()
        ns.idhex = (ns.idhash + "=").decode("base64").encode("hex")
        ns.orport,ns.dirport = map(int, (ns.orport,ns.dirport))
        m = re.search(r"(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)", updated)
        ns.updated = datetime.datetime(*map(int, m.groups()))
        m = re.search(r"^s((?:\s\S*)+)", nsline, re.M)
        flags = m.groups()
        ns.flags = flags[0].strip().split(" ")
        nslist.append(ns)
    return nslist

class EventHandler:
    """An 'EventHandler' wraps callbacks for the events Tor can return."""
    def __init__(self):
        """Create a new EventHandler."""
        self._map1 = {
            "CIRC" : self.circ_status,
            "STREAM" : self.stream_status,
            "ORCONN" : self.or_conn_status,
            "BW" : self.bandwidth,
            "DEBUG" : self.msg,
            "INFO" : self.msg,
            "NOTICE" : self.msg,
            "WARN" : self.msg,
            "ERR" : self.msg,
            "NEWDESC" : self.new_desc,
            "ADDRMAP" : self.address_mapped,
            "NS" : self.ns
            }

    def handle1(self, lines):
        """Dispatcher: called from Connection when an event is received."""
        for code, msg, data in lines:
            evtype, args = self.decode1(msg, data)
            self._map1.get(evtype, self.unknown_event)(evtype, *args)

    def decode1(self, body, data):
        """Unpack an event message into a type/arguments-tuple tuple."""
        if " " in body:
            evtype,body = body.split(" ",1)
        else:
            evtype,body = body,""
        evtype = evtype.upper()
        if evtype == "CIRC":
            m = re.match(r"(\d+)\s+(\S+)(\s\S+)?(\s\S+)?(\s\S+)?", body)
            if not m:
                raise ProtocolError("CIRC event misformatted.")
            ident,status,path,reason,remote = m.groups()
            ident = int(ident)
            if path:
                if path.find("REASON=") != -1:
                    remote = reason
                    reason = path
                    path=[]
                else:
                    path = path.strip().split(",")
            else:
                path = []
            if reason: reason = reason[8:]
            if remote: remote = remote[15:]
            args = ident, status, path, reason, remote
        elif evtype == "STREAM":
            m = re.match(r"(\S+)\s+(\S+)\s+(\S+)\s+(\S+):(\d+)(\s\S+)?(\s\S+)?", body)
            if not m:
                raise ProtocolError("STREAM event misformatted.")
            ident,status,circ,target_host,target_port,reason,remote = m.groups()
            ident,circ = map(int, (ident,circ))
            if reason: reason = reason[8:]
            if remote: remote = remote[15:]
            args = ident, status, circ, target_host, int(target_port), reason, remote
        elif evtype == "ORCONN":
            m = re.match(r"(\S+)\s+(\S+)", body)
            if not m:
                raise ProtocolError("ORCONN event misformatted.")
            target, status = m.groups()
            args = status, target
        elif evtype == "BW":
            m = re.match(r"(\d+)\s+(\d+)", body)
            if not m:
                raise ProtocolError("BANDWIDTH event misformatted.")
            read, written = map(long, m.groups())
            args = read, written
        elif evtype in ("DEBUG", "INFO", "NOTICE", "WARN", "ERR"):
            args = evtype, body
        elif evtype == "NEWDESC":
            args = (body.split(" "),)
        elif evtype == "ADDRMAP":
            m = re.match(r'(\S+)\s+(\S+)\s+(\"[^"]+\"|\w+)')
            if not m:
                raise ProtocolError("BANDWIDTH event misformatted.")
            fromaddr, toaddr, when = m.groups()
            if when.upper() == "NEVER":
                when = None
            else:
                when = time.localtime(
                    time.strptime(when[1:-1], "%Y-%m-%d %H:%M:%S"))
            args = fromaddr, toaddr, when
        elif evtype == "NS":
            args = (parse_ns_body(data),)
        else:
            args = (body,)

        return evtype, args

    def unknown_event(self, eventtype, evtype, *args):
        """Called when we get an event type we don't recognize.  This
           is almost alwyas an error.
        """
        raise NotImplemented

    def circ_status(self, eventtype, circID, status, path, reason, remote):
        """Called when a circuit status changes if listening to CIRCSTATUS
           events.  'status' is a member of CIRC_STATUS; circID is a numeric
           circuit ID, and 'path' is the circuit's path so far as a list of
           names.
        """
        raise NotImplemented

    def stream_status(self, eventtype, streamID, status, circID, target_host, target_port, reason, remote):
        """Called when a stream status changes if listening to STREAMSTATUS
           events.  'status' is a member of STREAM_STATUS; streamID is a
           numeric stream ID, and 'target' is the destination of the stream.
        """
        raise NotImplemented

    def or_conn_status(self, eventtype, status, target):
        """Called when an OR connection's status changes if listening to
           ORCONNSTATUS events. 'status' is a member of OR_CONN_STATUS; target
           is the OR in question.
        """
        raise NotImplemented

    def bandwidth(self, eventtype, read, written):
        """Called once a second if listening to BANDWIDTH events.  'read' is
           the number of bytes read; 'written' is the number of bytes written.
        """
        raise NotImplemented

    def new_desc(self, eventtype, identities):
        """Called when Tor learns a new server descriptor if listenting to
           NEWDESC events.
        """
        raise NotImplemented

    def msg(self, eventtype, severity, message):
        """Called when a log message of a given severity arrives if listening
           to INFO_MSG, NOTICE_MSG, WARN_MSG, or ERR_MSG events."""
        raise NotImplemented

    def ns(self, eventtype, nslist):
        raise NotImplemented

    def address_mapped(self, eventtype, fromAddr, toAddr, expiry=None):
        """Called when Tor adds a mapping for an address if listening
           to ADDRESSMAPPED events.
        """
        raise NotImplemented


class DebugEventHandler(EventHandler):
    """Trivial debug event handler: reassembles all parsed events to stdout."""
    def circ_status(self, eventtype, circID, status, path, reason, remote):
        output = [eventtype, str(circID), status]
        if path: output.append(",".join(path))
        if reason: output.append("REASON=" + reason)
        if remote: output.append("REMOTE_REASON=" + remote)
        print " ".join(output)

    def stream_status(self, eventtype, streamID, status, circID, target_host, target_port, reason, remote):
        output = [eventtype, str(streamID), status, str(circID), target_host,
str(target_port)]
        if reason: output.append("REASON=" + reason)
        if remote: output.append("REMOTE_REASON=" + remote)
        print " ".join(output)

    def ns(self, eventtype, nslist):
        for ns in nslist:
            print " ".join((eventtype, ns.name, ns.idhash,
              ns.updated.isoformat(), ns.ip, str(ns.orport),
              str(ns.dirport), " ".join(ns.flags)))

    def new_desc(self, eventtype, identities):
        print " ".join((eventtype, " ".join(identities)))

def parseHostAndPort(h):
    """Given a string of the form 'address:port' or 'address' or
       'port' or '', return a two-tuple of (address, port)
    """
    host, port = "localhost", 9100
    if ":" in h:
        i = h.index(":")
        host = h[:i]
        try:
            port = int(h[i+1:])
        except ValueError:
            print "Bad hostname %r"%h
            sys.exit(1)
    elif h:
        try:
            port = int(h)
        except ValueError:
            host = h

    return host, port

def get_connection(sock):
    """Given a socket attached to a Tor control port, detect the version of Tor
       and return an appropriate 'Connection' object."""
    return Connection(sock)

def run_example(host,port):
    print "host is %s:%d"%(host,port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    c = get_connection(s)
    c.set_event_handler(DebugEventHandler())
    th = c.launch_thread()
    c.authenticate()
    print "nick",`c.get_option("nickname")`
    print `c.get_info("version")`
    #print `c.get_info("desc/name/moria1")`
    print `c.get_info("network-status")`
    print `c.get_info("addr-mappings/all")`
    print `c.get_info("addr-mappings/config")`
    print `c.get_info("addr-mappings/cache")`
    print `c.get_info("addr-mappings/control")`

    print `c.extend_circuit(0,["moria1"])`
    try:
        print `c.extend_circuit(0,[""])`
    except ErrorReply: # wtf?
        print "got error. good."
    except:
        print "Strange error", sys.exc_info()[0]
   
    #send_signal(s,1)
    #save_conf(s)

    #set_option(s,"1")
    #set_option(s,"bandwidthburstbytes 100000")
    #set_option(s,"runasdaemon 1")
    #set_events(s,[EVENT_TYPE.WARN])
    c.set_events([EVENT_TYPE.STREAM, EVENT_TYPE.CIRC,
                  EVENT_TYPE.NS, EVENT_TYPE.NEWDESC], True)

    th.join()
    return

if __name__ == '__main__':
    import socket
    if len(sys.argv) > 2:
        print "Syntax: TorControl.py torhost:torport"
        sys.exit(0)
    else:
        sys.argv.append("localhost:9061")
    sh,sp = parseHostAndPort(sys.argv[1])
    run_example(sh,sp)

