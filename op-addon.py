#!/usr/bin/python
"""
  RWTH Aachen University, Informatik IV
  Copyright (C) 2007 Johannes Renner 
  Contact: renner@i4.informatik.rwth-aachen.de
"""
# Addon for Onion Proxies (prototype-v0.0-alpha):
# Shall eventually improve the performance of anonymous communications 
# and browsing by measuring RTTs of circuits/links, receiving infos
# from or-addons/alternate directory, building fast circuits from all 
# of these infos and attaching streams to fast circuits.

# TODO: import 'with'-statement for Lock objects? (with some_lock: do something)
import re
import sys
import math
import time
import sched
import struct
import socket
import threading
import Queue
# Non-standard packages
import socks
import GeoIP
#import networkx

from TorCtl import *
from TorCtl.TorUtil import *
from TorCtl.PathSupport import *

# Move these to config file
control_host = "127.0.0.1"
control_port = 9051
socks_host = "127.0.0.1"
socks_port = 9050
# Any ideas/proposals?
ping_dummy_host = "127.0.0.1"
ping_dummy_port = 100

# Close circ after n timeouts
timeout_limit = 3
# Slow RTT: 1 second?? 
slow = 1
# Set interval between work loads
sleep_interval = 10
# No of idle circuits
idle_circuits = 8

# GeoIP data object
geoip = GeoIP.new(GeoIP.GEOIP_STANDARD)
# TODO: Load the big database for more detailed info?
#geoip = GeoIP.open("./GeoLiteCity.dat", GeoIP.GEOIP_STANDARD)

# Lock object for regulating access to the circuit list
circs_lock = threading.Lock()

# Configure Selection Manager here!!
# Do NOT modify this object directly after it is handed to 
# PathBuilder, Use PathBuilder.schedule_selmgr instead.
__selmgr = PathSupport.SelectionManager(
      pathlen=3,
      order_exits=True,
      percent_fast=100,
      percent_skip=0,
      min_bw=1024,
      use_all_exits=False,
      uniform=True,
      use_exit=None,
      use_guards=False)

######################################### BEGIN: Connection         #####################

class Connection(TorCtl.Connection):
  def build_circuit(self, pathlen, path_sel):
    circ = Circuit()
    if pathlen == 1:
      circ.exit = path_sel.exit_chooser(circ.path)
      circ.path = [circ.exit]
      circ.circ_id = self.extend_circuit(0, circ.id_path())
    else:
      circ.path.append(path_sel.entry_chooser(circ.path))
      for i in xrange(1, pathlen-1):
        circ.path.append(path_sel.middle_chooser(circ.path))
      circ.exit = path_sel.exit_chooser(circ.path)
      circ.path.append(circ.exit)
      circ.circ_id = self.extend_circuit(0, circ.id_path())
    return circ

######################################### END: Connection          #####################
######################################### Router, Circuit, Stream  #####################

# Router class extended to GeoIP
class GeoIPRouter(TorCtl.Router):  
  def __init__(self, router): # Promotion constructor :)
    self.__dict__ = router.__dict__
    # Set the country code
    self.country_code = self.get_country()

  # Convert long int to dotted quad string
  def get_ip_dotted(self):
    return socket.inet_ntoa(struct.pack('L', self.ip))
  
  # Get the country-code from GeoIP on the fly
  def get_country(self):
    ip = self.get_ip_dotted()
    country = geoip.country_code_by_addr(ip)
    #record = geoip.record_by_addr(ip)
    #if record != None:
    #  country = record['country_code3']
    #plog("DEBUG", "Set country of router " + self.nickname + " (" + ip + "): " + str(country))
    return country

# Circuit class extended to RTTs
class Circuit(PathSupport.Circuit):  
  def __init__(self):
    PathSupport.Circuit.__init__(self)
    self.total_rtt = None      # double (sec), substitute with..
    self.rtts = []             # list of partial rtts: 1-2-3
    self.timeout_counter = 0   # timeout limit
    self.slowness_counter = 0  # slowness limit
    self.closed = False        # Mark circuits closed

# Stream class extended to isPing
class Stream(PathSupport.Stream):
  def __init__(self, sid, host, port, kind):
    PathSupport.Stream.__init__(self, sid, host, port, kind)
    self.isPing = False
    self.hop = None	# Save hop if this is a ping, None = complete circ

######################################### Router, Circuit, Stream  #####################
######################################### BEGIN: Pinger            #####################

# A simple "Pinger": try to connect 
# to somewhere via Tor using Socks4a
class Pinger:
  # Constructor
  def __init__(self, host, port):
    self.connect_host = host
    self.connect_port = port

  # Hmm, there is no "try .. except .. finally .." in Python < 2.5 !!  
  def ping(self):
    s = None
    try:
      try:
        s = socks.socksocket()
        s.setproxy(socks.PROXY_TYPE_SOCKS4, socks_host, socks_port)
        s.connect((self.connect_host, self.connect_port))
      except socks.Socks4Error, e:
	# Don't do nothing, this will actually happen
	# print("Got Exception: " + str(e))
	pass
    finally:
      # Close the socket if open
      if s:
        s.close()

######################################### END: Pinger              #####################
######################################### BEGIN: NetworkModel      #####################

# This will be used to record measured RTTs
# of single links and to find fast routes
class NetworkModel:  
  def __init__(self):
    # TODO: Use XDiGraph()
    self.graph = networkx.XGraph(selfloops=False, multiedges=False)
    # Add this OP to the model
    self.addRouter("ROOT")
    plog("DEBUG", "NetworkModel initiated")

  def addRouter(self, router):
    self.graph.add_node(router)

  def addLink(self, source, dest):
    self.graph.add_edge(source, dest)
    
######################################### END: NetworkModel        #####################
######################################### BEGIN: EventHandler      #####################

# We need an EventHandler, this one extends PathBuilder
class EventHandler(PathSupport.PathBuilder):  
  def __init__(self, c, selmgr):    
    # Call constructor of superclass
    PathBuilder.__init__(self, c, selmgr, GeoIPRouter)
    # Additional stuff
    self.ping_circs = Queue.Queue()  # (circ_id, hop)-pairs
    self.start_times = {}            # dict mapping (circ_id, hop):start_time TODO: cleanup
    self.circs_sorted = []           # sorted list of circs, generated regularly
    # Set up the CircuitManager
    self.circ_manager = CircuitManager(selmgr, c, self)
    self.circ_manager.setDaemon(True)
    self.circ_manager.start()
 
  # Add a circuit to ping, ping_info is (circ_id, hop)
  def queue_ping_circ(self, ping_info):
    self.ping_circs.put(ping_info)

  # Send signal "CLEARDNSCACHE"
  def clear_dns_cache(self):
    lines = self.c.sendAndRecv("SIGNAL CLEARDNSCACHE\r\n")
    for _, msg, more in lines:
      plog("DEBUG", "CLEARDNSCACHE: " + msg)
  
  # Sort a list by a specified key
  def sort_list(self, list, key):
    list.sort(lambda x,y: cmp(key(x), key(y))) # Python < 2.4 hack
    return list

  # Call after each measuring
  def refresh_sorted_list(self):
    # Sort the list for RTTs
    circs_lock.acquire()
    self.circs_sorted = self.sort_list(self.circuits.values(), lambda x: x.total_rtt)
    circs_lock.release()
    plog("DEBUG", "Refreshed sorted list of circuits")
  
  # Do something when circuit-events occur
  def circ_status_event(self, c):
    circs_lock.acquire()
    # Construct output for logging
    output = [c.event_name, str(c.circ_id), c.status]
    if c.path: output.append(",".join(c.path))
    if c.reason: output.append("REASON=" + c.reason)
    if c.remote_reason: output.append("REMOTE_REASON=" + c.remote_reason)
    plog("DEBUG", " ".join(output))
    # Circuits we don't control get built by Tor
    if c.circ_id not in self.circuits:
      plog("DEBUG", "Ignoring circuit " + str(c.circ_id) + " (controlled by Tor or not yet in the list)")
      circs_lock.release()
      return
    if c.status == "EXTENDED":
      self.circuits[c.circ_id].last_extended_at = c.arrived_at
    elif c.status == "FAILED" or c.status == "CLOSED":
      # XXX: Can still get a STREAM FAILED for this circ after this
      circ = self.circuits[c.circ_id]
      del self.circuits[c.circ_id]
      # Refresh the list
      #self.refresh_sorted_list()
      for stream in circ.pending_streams:
        plog("DEBUG", "Finding new circ for " + str(stream.strm_id))
	# TODO: What to do with pings?
	if not stream.isPing:
          self.attach_stream_any(stream, stream.detached_from)
      # TODO: Check if there are enough circs?
    elif c.status == "BUILT":
      # TODO: Perform a measuring directly?
      self.circuits[c.circ_id].built = True
      try:
        for stream in self.circuits[c.circ_id].pending_streams:
          self.c.attach_stream(stream.strm_id, c.circ_id)
      except TorCtl.ErrorReply, e:
        # No need to retry here. We should get the failed
        # event for either the circ or stream next
        plog("WARN", "Error attaching stream: " + str(e.args))
        circs_lock.release()
	return
    circs_lock.release()

  # Attach a regular user stream, moved here to play around
  def attach_stream_any(self, stream, badcircs):
    # To be able to always choose the fastest:
    # slows down attaching?
    self.clear_dns_cache()
    # Newnym, and warn if not built plus pending
    unattached_streams = [stream]
    if self.new_nym:
      self.new_nym = False
      plog("DEBUG", "Obeying new nym")
      circs_lock.acquire()
      for key in self.circuits.keys():
        if (not self.circuits[key].dirty and len(self.circuits[key].pending_streams)):
          plog("WARN", "New nym called, destroying circuit "+str(key)
             +" with "+str(len(self.circuits[key].pending_streams))
             +" pending streams")
          unattached_streams.extend(self.circuits[key].pending_streams)
          self.circuits[key].pending_streams.clear()
        # FIXME: Consider actually closing circ if no streams.
        self.circuits[key].dirty = True
      circs_lock.release()

    # Choose from the sorted list!  
    for circ in self.circs_sorted:
      if circ.built and circ.total_rtt and circ.circ_id not in badcircs and not circ.closed:
        if circ.exit.will_exit_to(stream.host, stream.port):
          try:
            self.c.attach_stream(stream.strm_id, circ.circ_id)
            stream.pending_circ = circ # Only one possible here
            circ.pending_streams.append(stream)
          except TorCtl.ErrorReply, e:
            # No need to retry here. We should get the failed
            # event for either the circ or stream next
            plog("WARN", "Error attaching stream: "+str(e.args))
            return
          break
	else:
	  plog("DEBUG", "Circuit " + str(circ.circ_id) + " won't exit")
    else:
      circ = None
      self.selmgr.set_target(stream.host, stream.port)
      while circ == None:
        try:
          circ = self.c.build_circuit(self.selmgr.pathlen, self.selmgr.path_selector)
        except TorCtl.ErrorReply, e:
          # FIXME: How come some routers are non-existant? Shouldn't
          # we have gotten an NS event to notify us they disappeared?
          plog("NOTICE", "Error building circ: "+str(e.args))
      for u in unattached_streams:
        plog("DEBUG", "Attaching "+str(u.strm_id)+" pending build of "+str(circ.circ_id))
        u.pending_circ = circ
      circ.pending_streams.extend(unattached_streams)
      circs_lock.acquire()
      self.circuits[circ.circ_id] = circ
      circs_lock.release()
    self.last_exit = circ.exit

  # Handle a ping stream
  def attach_ping(self, stream):
    plog("DEBUG", "New ping request")
    # Get info from the Queue
    # TODO: check if empty
    ping_info = self.ping_circs.get()
    # Extract ping-infos
    circ_id = ping_info[0]
    hop = ping_info[1]
    # Set circ to stream
    stream.circ = circ_id
    try:
      circs_lock.acquire()
      # Get the circuit, TODO: Handle circs that do not exist anymore!
      if circ_id in self.circuits:
        circ = self.circuits[circ_id]
        if circ.built and not circ.closed:        
          self.c.attach_stream(stream.strm_id, circ.circ_id, hop)
          # Measure here or move to before attaching?
          self.start_times[(circ_id, hop)] = time.time()
	  stream.hop = hop
          stream.pending_circ = circ # Only one possible here
          circ.pending_streams.append(stream)
        else:
          plog("WARN", "Circuit not built")
      else:
        plog("WARN", "Circuit does not exist")
      circs_lock.release()
    except TorCtl.ErrorReply, e:
      plog("WARN", "Error attaching stream: " + str(e.args))

  # Catch stream status events
  def stream_status_event(self, s):
    # Construct debugging output
    output = [s.event_name, str(s.strm_id), s.status, str(s.circ_id), s.target_host, str(s.target_port)]
    if s.reason: output.append("REASON=" + s.reason)
    if s.remote_reason: output.append("REMOTE_REASON=" + s.remote_reason)
    plog("DEBUG", " ".join(output))
    
    # If target_host is not an IP-address
    if not re.match(r"\d+.\d+.\d+.\d+", s.target_host):
      s.target_host = "255.255.255.255" # ignore DNS for exit policy check
    
    # NEW or NEWRESOLVE
    if s.status == "NEW" or s.status == "NEWRESOLVE":
      if s.status == "NEWRESOLVE" and not s.target_port:
        s.target_port = self.resolve_port      
      # Set up the new stream
      stream = Stream(s.strm_id, s.target_host, s.target_port, s.status)
      self.streams[s.strm_id] = stream        
      # (Double-)Check if this is a ping stream
      if (stream.host == ping_dummy_host) & (stream.port == ping_dummy_port):
        # Set isPing
	stream.isPing = True
        self.attach_ping(stream)
      else:
        self.attach_stream_any(self.streams[s.strm_id], self.streams[s.strm_id].detached_from)
    
    # DETACHED
    elif s.status == "DETACHED":
      # Stream not found
      if s.strm_id not in self.streams:
        plog("WARN", "Detached stream " + str(s.strm_id) + " not found")
        self.streams[s.strm_id] = Stream(s.strm_id, s.target_host, s.target_port, "NEW")
      # s.circ_id not found
      if not s.circ_id:
        plog("WARN", "Stream " + str(s.strm_id) + " detached from no circuit!")
      else:
        self.streams[s.strm_id].detached_from.append(s.circ_id)

      # If this is a ping
      if self.streams[s.strm_id].isPing:
        circs_lock.acquire()
        if (s.reason == "TIMEOUT"):
	  self.circuits[s.circ_id].timeout_counter += 1
	  self.circuits[s.circ_id].slowness_counter += 1
	  plog("DEBUG", str(self.circuits[s.circ_id].timeout_counter) + " timeout(s) on circuit " + str(s.circ_id))
	  if self.circuits[s.circ_id].timeout_counter >= timeout_limit:
	    # Close the circuit
	    plog("DEBUG", "Reached limit on timeouts --> closing circuit " + str(s.circ_id))
	    self.circuits[s.circ_id].closed = True
	    self.c.close_circuit(s.circ_id)
	  # Set RTT for circ to None
	  self.circuits[s.circ_id].total_rtt = None
	  circs_lock.release()
	  # Only close the stream
          self.c.close_stream(s.strm_id, 7)
	  return
        # This is a successful ping: measure here
	now = time.time()
	rtt = now - self.start_times[(s.circ_id, self.streams[s.strm_id].hop)]
        plog("INFO", "Measured RTT: " + str(rtt) + " sec")
	# Save RTT to circuit
	self.circuits[s.circ_id].total_rtt = rtt
	
	# Close if slow-max is reached
        if rtt >= slow:
	  self.circuits[s.circ_id].slowness_counter += 1
	  if self.circuits[s.circ_id].slowness_counter >= timeout_limit:
	    plog("DEBUG", "Slow-max is reached --> closing circuit " + str(s.circ_id))
	    self.circuits[s.circ_id].closed = True
	    self.c.close_circuit(s.circ_id)
	circs_lock.release()
	# Resort every time ??
	self.refresh_sorted_list()
	# Close the stream
        self.c.close_stream(s.strm_id, 6)
	return
      
      # Detect timeouts on user streams
      if s.reason == "TIMEOUT":
        circs_lock.acquire()
	self.circuits[s.circ_id].timeout_counter += 1
	plog("DEBUG", str(self.circuits[s.circ_id].timeout_counter) + " timeout(s) on circuit " + str(s.circ_id))
	if self.circuits[s.circ_id].timeout_counter >= timeout_limit:
	  # Close the circuit
	  plog("DEBUG", "Reached limit on timeouts --> closing circuit " + str(s.circ_id))
	  self.circuits[s.circ_id].closed = True
	  self.c.close_circuit(s.circ_id)
	circs_lock.release()

      # Stream was pending
      if self.streams[s.strm_id] in self.streams[s.strm_id].pending_circ.pending_streams:
        self.streams[s.strm_id].pending_circ.pending_streams.remove(self.streams[s.strm_id])
      # Attach to another circ
      self.streams[s.strm_id].pending_circ = None
      self.attach_stream_any(self.streams[s.strm_id], self.streams[s.strm_id].detached_from)
    
    # SUCCEEDED
    elif s.status == "SUCCEEDED":
      if s.strm_id not in self.streams:
        plog("NOTICE", "Succeeded stream " + str(s.strm_id) + " not found")
        return
      if s.circ_id and self.streams[s.strm_id].pending_circ.circ_id != s.circ_id:
        # Hrmm.. this can happen on a new-nym.. Very rare, putting warn
        # in because I'm still not sure this is correct
        plog("WARN", "Mismatch of pending: "
          + str(self.streams[s.strm_id].pending_circ.circ_id) + " vs "
          + str(s.circ_id))
        circs_lock.acquire()
	self.streams[s.strm_id].circ = self.circuits[s.circ_id]
        circs_lock.release()
      else:
        self.streams[s.strm_id].circ = self.streams[s.strm_id].pending_circ
      self.streams[s.strm_id].pending_circ.pending_streams.remove(self.streams[s.strm_id])
      self.streams[s.strm_id].pending_circ = None
      self.streams[s.strm_id].attached_at = s.arrived_at
    
    # FAILED or CLOSED
    elif s.status == "FAILED" or s.status == "CLOSED":
      if s.strm_id not in self.streams:
        plog("NOTICE", "Failed stream " + str(s.strm_id) + " not found")
        return
      if (not s.circ_id) & (s.reason != "DONE"):
        plog("WARN", "Stream " + str(s.strm_id) + " closed/failed from no circuit!")
      # We get failed and closed for each stream. OK to return 
      # and let the CLOSED do the cleanup
      if s.status == "FAILED":
        # Avoid busted circuits that will not resolve or carry traffic
        self.streams[s.strm_id].failed = True
        circs_lock.acquire()
	if s.circ_id in self.circuits: self.circuits[s.circ_id].dirty = True
        elif self.streams[s.strm_id].attached_at != 0: 
	  plog("WARN","Failed stream on unknown circ " + str(s.circ_id))
        circs_lock.release()
	return
      # CLOSED
      if self.streams[s.strm_id].pending_circ:
        self.streams[s.strm_id].pending_circ.pending_streams.remove(self.streams[s.strm_id])
      # Actual removal of the stream
      del self.streams[s.strm_id]

    # REMAP
    elif s.status == "REMAP":
      if s.strm_id not in self.streams:
        plog("WARN", "Remap id "+str(s.strm_id)+" not found")
      else:
        if not re.match(r"\d+.\d+.\d+.\d+", s.target_host):
          s.target_host = "255.255.255.255"
          plog("NOTICE", "Non-IP remap for "+str(s.strm_id) + " to " + s.target_host)		   
        self.streams[s.strm_id].host = s.target_host
        self.streams[s.strm_id].port = s.target_port

######################################### END: EventHandler        #####################
######################################### BEGIN: CircuitManager    #####################

# This is the main class that keeps track of: 
# -- Connection to Tor
# -- EventHandler
#
# Does work regularly
# TODO: Switch circuit-managing off to get circuits created from Tor
# TODO: Add a NetworkModel to this!

class CircuitManager(threading.Thread):

  def __init__(self, selmgr, conn, event_handler):
    # Set everything
    self.selmgr = selmgr
    self.conn = conn
    self.handler = event_handler
    # Create the Pinger
    self.pinger = Pinger(ping_dummy_host, ping_dummy_port)
    # Call constructor of superclass
    threading.Thread.__init__(self)
  
  # The run()-method
  def run(self):
    while self.isAlive():
      self.do_work()
      time.sleep(sleep_interval)
 
  # Do the work
  def do_work(self):
    # Get number of circuits
    circs_lock.acquire()
    n = len(self.handler.circuits.values())
    circs_lock.release() 
    # Schedule (idle_circuits-n) circuit-buildups
    while (n < idle_circuits):      
      self.build_idle_circuit()
      plog("DEBUG", "Scheduled circuit No. " + str(n+1))
      n += 1
    # Measure RTTs of circuits
    self.measure()
    self.print_circuits()

  # Build an idle circuit
  # Better here than in EventHandler's thread
  def build_idle_circuit(self):
    circ = None
    while circ == None:
      try:
        # Build the circuit
        circ = self.conn.build_circuit(self.selmgr.pathlen, self.selmgr.path_selector)
        # Using lock:
	circs_lock.acquire()
	self.handler.circuits[circ.circ_id] = circ
        circs_lock.release()
      except TorCtl.ErrorReply, e:
        # FIXME: How come some routers are non-existant? Shouldn't
        # we have gotten an NS event to notify us they disappeared?
        plog("NOTICE", "Error building circ: " + str(e.args))

  # Measure RTTs of all circuits
  def measure(self):
    circs_lock.acquire()
    circs = self.handler.circuits.values()
    circs_lock.release()
    for c in circs:
      if c.built:
	id = c.circ_id
	# TODO: Measure for all hops, test if result is 
	# bigger each time, else start again
	# Put in the queue (circ, hop), XXX: synchronize!
	self.handler.queue_ping_circ((id, None))
        # Trigger ping
	self.pinger.ping()

  # Print circuits
  def print_circuits(self):
    circs_lock.acquire()
    circs = self.handler.circuits.values()
    plog("INFO", "We have " + str(len(circs)) + " circuits")
    for c in circs:
      out = "+ Circuit " + str(c.circ_id) + ": "
      for r in c.path: out = out + " " + r.nickname + "(" + str(r.country_code) + ")"
      if c.total_rtt: out = out + " (RTT=" + str(c.total_rtt) + ")"
      if not c.built: out = out + " (not yet built)"
      print(out)
    circs_lock.release()

######################################### END: CircuitManager      #####################

# Return a connection to Tor's control port
def connect(control_host, control_port):
  # Create a socket and connect to Tor
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((control_host, control_port))
  return Connection(sock)
  
# Do the configuration
def configure(conn):
  # Set events to listen to
  conn.set_events([TorCtl.EVENT_TYPE.STREAM,
      TorCtl.EVENT_TYPE.CIRC,
      TorCtl.EVENT_TYPE.NS,	  
      TorCtl.EVENT_TYPE.NEWDESC], True)
  # Set options: We attach streams now & build circuits
  conn.set_option("__LeaveStreamsUnattached", "1")
  conn.set_option("__DisablePredictedCircuits", "1")

def startup(argv):
  # Connect to Tor process
  conn = connect(control_host, control_port)
  #conn.debug(file("control.log", "w"))
  conn.authenticate()
  # Set Handler to the connection
  handler = EventHandler(conn, __selmgr)
  conn.set_event_handler(handler)
  # Configure myself
  configure(conn)
  # Go to sleep to be able to get killed from the commandline
  try:
    while True:
      time.sleep(60)
  except KeyboardInterrupt:
    cleanup(conn)

# Call this on exit
def cleanup(conn):
  plog("INFO", "Cleaning up...")
  conn.set_option("__LeaveStreamsUnattached", "0")
  conn.set_option("__DisablePredictedCircuits", "0")
  conn.close()

if __name__ == '__main__':
  # Call main
  startup(sys.argv)
