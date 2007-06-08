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

# TODO: import 'with'-statement for Lock objects (Python 2.5: "with some_lock: do something")
import re
import sys
import copy
import math
import time
import random
import socket
import threading
import Queue
#import ConfigParser

# Non-standard packages
import socks
import networkx

# TorCtl
import TorCtl.PathSupport
import TorCtl.GeoIPSupport
from TorCtl import *
from TorCtl.TorUtil import plog, sort_list

# TODO: Move these to config-file
control_host = "127.0.0.1"
control_port = 9051
socks_host = "127.0.0.1"
socks_port = 9050
# Any ideas/proposals?
ping_dummy_host = "127.0.0.1"
ping_dummy_port = 100

# Close circ after n timeouts or avg measured slownesses
timeout_limit = 1
slowness_limit = 3
# Slow RTT := x seconds 
slow = 0.7
# Note: Tor-internal lifetime of a circuit is 10 min --> 600/sleep_interval = max-age
# Sleep interval between working loads in sec
sleep_interval = 5
# No of idle circuits to build preemptively
# TODO: Also configure ports to use
idle_circuits = 5

# Measure complete circuits
measure_circs = True
# Set to True if we want to measure partial circuits
measure_partial_circs = False

# Testing mode: Close circuits after num_tests measures + 
# involves a FileHandler to write collected data to a file
testing_mode = False
# Number of tests per circuit
num_tests = 5

# Do configuration here TODO: use my_country for src
# Set src_country below when setting up our location
path_config = GeoIPSupport.GeoIPConfig(unique_countries = True,
                                       src_country = None,
				       crossings = 1,
				       excludes = [])

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
      use_guards=True,
      geoip_config=path_config)

# Signalize that a round has finished
finished_event = threading.Event()

######################################### BEGIN: Connection         #####################

class Connection(TorCtl.Connection):
  """ Connection class that uses my Circuit class """
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

  def build_circuit_from_path(self, path):
    """ Build circuit using a given path shall be used to build circs from NetworkModel """
    circ = Circuit()
    circ.rtt_created = True
    # Set path to circuit
    circ.path = path
    # Set exit
    circ.exit = path[len(path)-1]
    if len(path) > 0:
      circ.circ_id = self.extend_circuit(0, circ.id_path())
    return circ

######################################### Stats                    #####################

class Stats:
  def __init__(self):
    self.values = []
    self.min = 0.0
    self.max = 0.0
    self.mean = 0.0
    self.dev = 0.0
    self.median = 0.0

  def add_value(self, value):
    # Append value
    self.values.append(value)
    # Set min & max
    if self.min == 0: self.min = value
    elif self.min > value: self.min = value
    if self.max < value: self.max = value
    # Refresh everything
    self.mean = self.get_mean()
    self.dev = self.get_dev()
    self.median = self.get_median()

  def get_mean(self):
    """ Compute mean from the values """
    if len(self.values) > 0:
      sum = reduce(lambda x, y: x+y, self.values, 0.0)
      return sum/len(self.values)
    else:
      return 0.0

  def get_dev(self):
    """ Return the stddev of the values """
    if len(self.values) > 1:
      mean = self.get_mean()
      sum = reduce(lambda x, y: x + ((y-mean)**2.0), self.values, 0.0)
      s = math.sqrt(sum/(len(self.values)-1))
      return s
    else:
      return 0.0

  def get_median(self):
    """ Return the median of the values """
    if len(self.values) > 0:
      self.values.sort()
      return self.values[(len(self.values)-1)/2]
    else: return 0.0

class FileHandler:
  """ FileHandler for appending collected data to a file """
  def __init__(self, filename):
    self.filename = filename

  def write(self, line):
    self.filehandle = open(self.filename, 'a')
    self.filehandle.write(line + "\n")
    self.filehandle.close() 

######################################### Circuit, Stream          #####################

class Circuit(PathSupport.Circuit): 
  """ Circuit class extended to RTTs and related stats """
  def __init__(self):
    PathSupport.Circuit.__init__(self)
    # RTT stuff
    self.part_rtts = {}		# dict of partial rtts, pathlen 3: 1-2-None
    self.current_rtt = None	# double (sec): current value
    self.stats = Stats()	# stats about total RTT contains history
    # Counters and flags
    self.age = 0		# age in rounds
    self.timeout_counter = 0	# timeout limit
    self.slowness_counter = 0 	# slowness limit
    self.closed = False		# mark circuit closed
    self.rtt_created = False	# if this was created from the model
 
  def add_rtt(self, rtt):
    """ Add a new value and refresh the stats """
    # Set current
    self.current_rtt = rtt
    # Add to the stats
    self.stats.add_value(rtt)
    # Increase age
    self.age += 1

  def to_string(self):
    """ Create a string representation """
    s = "Circuit " + str(self.circ_id) + ": "
    for r in self.path: s += " " + r.nickname + "(" + str(r.country_code) + ")"
    if not self.built: s += " (not yet built)"
    else: s += " (age=" + str(self.age) + ")"
    if self.current_rtt: 
      s += ": " "RTT current/median/mean/dev: "
      s += str(self.current_rtt) + "/" + str(self.stats.median) + "/"
      s += str(self.stats.mean) + "/" + str(self.stats.dev)
    if self.rtt_created: s += "*"
    return s

class Stream(PathSupport.Stream):
  """ Stream class extended to hop """
  def __init__(self, sid, host, port, kind):
    PathSupport.Stream.__init__(self, sid, host, port, kind)
    self.hop = None		# save hop if this is a ping, hop=None means complete circ

######################################### BEGIN: NetworkModel      #####################

class LinkInfo:
  """ This class contains infos about a link: source, destination, RTT
      plus: rtt_history, methods to compute stats, etc. """
  def __init__(self, src, dest, rtt=0):
    # Set src and dest
    self.src = src
    self.dest = dest
    # The current value
    self.current_rtt = 0.0
    # Setup the stats and record the first RTT
    self.stats = Stats()
    self.add_rtt(rtt)

  def add_rtt(self, rtt):
    self.current_rtt = rtt
    self.stats.add_value(rtt)

class PathProposal:
  """ Instances of this class are path-proposals """
  def __init__(self, links, path):
    # This is a list of LinkInfo objects
    self.links = links
    # Also save the path for passing to build_circuit, cut off ROOT
    self.path = path[1:len(path)]
    # Compute the expected RTT (from current value?)
    self.rtt = reduce(lambda x,y: x + y.current_rtt, self.links, 0.0)
  
  def to_string(self):
    """ Create a string for printing out information """
    s = ""
    for l in self.links:
      # Get the single objects
      s += l.src.nickname + "--" + l.dest.nickname + " (" + str(l.current_rtt) + ") " + ", "
    return "Route proposal: " + s + "--> " + str(self.rtt) + " sec" 

class NetworkModel:  
  """ This class is used to record measured RTTs for single links in a model of the 
      'currently explored subnet' (currently this is an undirected graph!) """  
  def __init__(self, rooter):
    """ Constructor: pass the root of all our circuits """
    # Use XDiGraph() (= directed)?
    self.graph = networkx.XGraph(name="Explored Tor Subnet", selfloops=False, multiedges=False)
    # Initially add THIS proxy to the model
    self.root = rooter
    self.graph.add_node(self.root)
    self.proposals = []
    plog("DEBUG", "NetworkModel initiated: added " + self.root.nickname)

  def add_link(self, src, dest, rtt):
    """ Add a link to the graph given src, dest & rtt """
    self.graph.add_edge(src, dest, LinkInfo(src, dest, rtt))

  def get_link_info(self, path):
    """ From a path given as list of routers, return link-infos """
    links = []
    for i in xrange(0, len(path)-1):
      # TODO: Check if edge exists
      links.append(self.graph.get_edge(path[i], path[i+1]))
    return links

  def find_circuits(self):
    # Reset list of proposals and prefixes for DFS
    self.proposals = []
    self.prefixes = {}
    # Start the search
    self.visit(self.root, [])
    # Sort proposals for their RTTs
    sort_list(self.proposals, lambda x: x.rtt)
    # Print all of them for debugging/info
    for p in self.proposals:
      print(p.to_string())

  def check_proposals(self, n):
    """ Return all proposals with rtt <= n seconds """
    ret = []
    for p in self.proposals:
      if p.rtt <= n:
	ret.append(p) 
    plog("DEBUG", "Found " + str(len(ret)) + " path proposals having RTT <= " + str(n) + " sec")
    return ret

  def visit(self, node, path, i=1):
    """ Recursive Depth-First-Search: Maybe use some existing method? """
    if node not in path:
      path.append(node)
      # Root -- Exit
      if len(path) == 4:
        # We found a possible circuit: add to the proposals
        self.proposals.append(PathProposal(self.get_link_info(path), path))
      else:
        self.prefixes[i] = path
	# G is also a dict
        for n in self.graph[node]:
	  if n not in self.prefixes[i]:
	    self.visit(n, copy.copy(self.prefixes[i]), i+1)

  def print_graph(self):
    """ Print current info about the graph """
    print(self.graph.info())
    #for e in self.graph.edges():
    #  src, dest, link = e
    #  plog("INFO", "Edge: " + src.nickname + " -- " + dest.nickname + ", RTT = " + str(link.rtt) + " sec")

######################################### BEGIN: EventHandlers     #####################

# TODO: Store the number of circuits here
class CircuitHandler(PathSupport.PathBuilder):
  """ CircuitHandler that extends from PathBuilder """
  def __init__(self, c, selmgr):
    # Init the PathBuilder
    PathSupport.PathBuilder.__init__(self, c, selmgr, GeoIPSupport.GeoIPRouter)    
    self.circs_sorted = []	# list of circs sorted by mean RTT
    self.check_circuit_pool()	# bring up the pool of circs
 
  def check_circuit_pool(self):
    """ Init or check the status of our pool of circuits """
    # Get current number of circuits
    n = len(self.circuits.values())
    i = idle_circuits-n
    if i > 0:
      plog("INFO", "Checked pool of circuits: we need to build " + str(i) + " circuits")
    # Schedule (idle_circuits-n) circuit-buildups
    while (n < idle_circuits):      
      self.build_idle_circuit()
      plog("DEBUG", "Scheduled circuit No. " + str(n+1))
      n += 1

  def check_path(self, path):
    """ Check if we already have a circuit with this path """
    for c in self.circuits.values():
      if c.path == path:
        return False
    return True

  def build_idle_circuit(self):
    """ Build an idle circuit """
    circ = None
    while circ == None:
      try:
        if measure_partial_circs:
	  # Get the proposals RTT <= 0.5
	  proposals = self.model.check_proposals(slow)
	  # TODO: Ensure we also create new paths (check number of circs with rtt_created)
	  # TODO: Check if we have > m proposals
	  while len(proposals) > 0:
	    choice = random.choice(proposals)
	    # Check if we already have a circ with this path
	    if self.check_path(choice.path):
	      plog("INFO", "Chosen proposal: " + choice.to_string())
	      circ = self.c.build_circuit_from_path(choice.path)
	      self.circuits[circ.circ_id] = circ
	      return
	    else:
	      plog("DEBUG", "Proposed circuit already exists")
	      # Remove from the proposals
	      proposals.remove(choice)
	  plog("DEBUG", "Falling back to normal path selection") 

        # Build the circuit
	self.selmgr.set_target("255.255.255.255", 80)
        circ = self.c.build_circuit(self.selmgr.pathlen, self.selmgr.path_selector)
	self.circuits[circ.circ_id] = circ
      except TorCtl.ErrorReply, e:
        # FIXME: How come some routers are non-existant? Shouldn't
        # we have gotten an NS event to notify us they disappeared?
        plog("NOTICE", "Error building circuit: " + str(e.args))

  def print_circuits(self):
    """ Print out our circuits plus some info """
    circs = self.circuits.values()
    plog("INFO", "We have " + str(len(circs)) + " circuits:")
    for c in circs:
      print("+ " + c.to_string())

  def refresh_sorted_list(self):
    """ Sort the list for their mean RTTs """
    self.circs_sorted = sort_list(self.circuits.values(), lambda x: x.stats.mean)
    plog("DEBUG", "Refreshed sorted list of circuits")
 
  def circ_status_event(self, c):
    """ Handle circuit status events """
    # Construct output for logging
    output = [c.event_name, str(c.circ_id), c.status]
    if c.path: output.append(",".join(c.path))
    if c.reason: output.append("REASON=" + c.reason)
    if c.remote_reason: output.append("REMOTE_REASON=" + c.remote_reason)
    plog("DEBUG", " ".join(output))
    
    # Circuits we don't control get built by Tor
    if c.circ_id not in self.circuits:
      plog("DEBUG", "Ignoring circuit " + str(c.circ_id) + " (controlled by Tor or not yet in the list)")
      return
    
    # EXTENDED
    if c.status == "EXTENDED":
      self.circuits[c.circ_id].last_extended_at = c.arrived_at
    
    # FAILED & CLOSED
    elif c.status == "FAILED" or c.status == "CLOSED":
      # XXX: Can still get a STREAM FAILED for this circ after this
      circ = self.circuits[c.circ_id]
      # Actual removal of the circ
      del self.circuits[c.circ_id]
      # Give away pending streams
      for stream in circ.pending_streams:
	plog("DEBUG", "Finding new circ for " + str(stream.strm_id))
        self.attach_stream_any(stream, stream.detached_from)
      # Refresh the list 
      self.refresh_sorted_list()
      # Check if there are enough circs
      self.check_circuit_pool()
      return
    
    # BUILT
    elif c.status == "BUILT":
      self.circuits[c.circ_id].built = True
      try:
        for stream in self.circuits[c.circ_id].pending_streams:
          self.c.attach_stream(stream.strm_id, c.circ_id)
      except TorCtl.ErrorReply, e:
        # No need to retry here. We should get the failed
        # event for either the circ or stream next
        plog("WARN", "Error attaching stream: " + str(e.args))
	return
    
    # OTHER?
    else:
      # If this was e.g. a LAUNCHED
      pass

######################################### BEGIN: StreamHandler      #####################

class StreamHandler(CircuitHandler):
  """ This is a StreamHandler that extends from the CircuitHandler """
  def __init__(self, c, selmgr):    
    # Call constructor of superclass
    CircuitHandler.__init__(self, c, selmgr)
    # NEWNYM is needed for testing bandwidth
    #self.new_nym = True
 
  def clear_dns_cache(self):
    """ Send signal CLEARDNSCACHE """
    lines = self.c.sendAndRecv("SIGNAL CLEARDNSCACHE\r\n")
    for _, msg, more in lines:
      plog("DEBUG", "CLEARDNSCACHE: " + msg)

  def attach_stream_any(self, stream, badcircs):
    """ Attach a regular user stream """
    # To be able to always choose the fastest: slows down attaching?
    #self.clear_dns_cache()
    # Newnym, and warn if not built plus pending
    unattached_streams = [stream]
    if self.new_nym:
      self.new_nym = False
      plog("DEBUG", "Obeying new nym")
      for key in self.circuits.keys():
        if (not self.circuits[key].dirty and len(self.circuits[key].pending_streams)):
          plog("WARN", "New nym called, destroying circuit "+str(key)
             +" with "+str(len(self.circuits[key].pending_streams))
             +" pending streams")
          unattached_streams.extend(self.circuits[key].pending_streams)
          self.circuits[key].pending_streams.clear()
        # FIXME: Consider actually closing circ if no streams.
        self.circuits[key].dirty = True

    # Choose from the sorted list
    # TODO: We don't have a sorted list if we don't measure!
    for circ in self.circs_sorted:
      # Only attach if we already measured
      if circ.built and not circ.closed and circ.circ_id not in badcircs and circ.current_rtt:
        if circ.exit.will_exit_to(stream.host, stream.port):
          try:
            self.c.attach_stream(stream.strm_id, circ.circ_id)
            stream.pending_circ = circ # Only one possible here
            circ.pending_streams.append(stream)
	    # Clear cache after the attach?
	    self.clear_dns_cache()
          except TorCtl.ErrorReply, e:
            # No need to retry here. We should get the failed
            # event for either the circ or stream next
            plog("WARN", "Error attaching stream: " + str(e.args))
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
          plog("NOTICE", "Error building circ: " + str(e.args))
      for u in unattached_streams:
        plog("DEBUG", "Attaching " + str(u.strm_id) + " pending build of circuit " + str(circ.circ_id))
        u.pending_circ = circ      
      circ.pending_streams.extend(unattached_streams)
      # Problem here??
      self.circuits[circ.circ_id] = circ
    self.last_exit = circ.exit

  def stream_status_event(self, s):
    """ Catch user stream events """
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
      self.attach_stream_any(self.streams[s.strm_id], self.streams[s.strm_id].detached_from)
    
    # DETACHED
    elif s.status == "DETACHED":
      # Stream not found
      if s.strm_id not in self.streams:
        plog("WARN", "Detached stream " + str(s.strm_id) + " not found")
        self.streams[s.strm_id] = Stream(s.strm_id, s.target_host, s.target_port, "NEW")
      # Circuit not found
      if not s.circ_id:
        plog("WARN", "Stream " + str(s.strm_id) + " detached from no circuit!")
      else:
        self.streams[s.strm_id].detached_from.append(s.circ_id)      
      # Detect timeouts on user streams
      if s.reason == "TIMEOUT":
	# Increase a timeout counter on the stream?
	#self.circuits[s.circ_id].timeout_counter += 1
	plog("DEBUG", "User stream timed out on circuit " + str(s.circ_id))
      # Stream was pending
      if self.streams[s.strm_id] in self.streams[s.strm_id].pending_circ.pending_streams:
        self.streams[s.strm_id].pending_circ.pending_streams.remove(self.streams[s.strm_id])
      # Attach to another circ
      self.streams[s.strm_id].pending_circ = None
      self.attach_stream_any(self.streams[s.strm_id], self.streams[s.strm_id].detached_from)

    # SUCCEEDED
    if s.status == "SUCCEEDED":
      if s.strm_id not in self.streams:
        plog("NOTICE", "Succeeded stream " + str(s.strm_id) + " not found")
        return
      if s.circ_id and self.streams[s.strm_id].pending_circ.circ_id != s.circ_id:
        # Hrmm.. this can happen on a new-nym.. Very rare, putting warn
        # in because I'm still not sure this is correct
        plog("WARN", "Mismatch of pending: "
          + str(self.streams[s.strm_id].pending_circ.circ_id) + " vs "
          + str(s.circ_id))
	self.streams[s.strm_id].circ = self.circuits[s.circ_id]
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
      #if not s.circ_id: plog("WARN", "Stream " + str(s.strm_id) + " closed/failed from no circuit")
      # We get failed and closed for each stream. OK to return 
      # and let the CLOSED do the cleanup
      if s.status == "FAILED":
        # Avoid busted circuits that will not resolve or carry traffic
        self.streams[s.strm_id].failed = True
	if s.circ_id in self.circuits: self.circuits[s.circ_id].dirty = True
        elif self.streams[s.strm_id].attached_at != 0: 
	  plog("WARN", "Failed stream on unknown circuit " + str(s.circ_id))
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

######################################### BEGIN: PingHandler       #####################

class PingHandler(StreamHandler):
  """ This class extends the general StreamHandler to handle ping-requests """
  def __init__(self, c, selmgr, router):
    # Anything ping-related
    self.ping_queue = Queue.Queue()	# (circ_id, hop)-pairs
    self.start_times = {}		# dict mapping (circ_id, hop):start_time TODO: cleanup
    # Start the Pinger that triggers the connections
    self.pinger = Pinger(self)
    self.pinger.setDaemon(True)
    self.pinger.start()
    # Additional stuff for partial measurings
    if measure_partial_circs:
      self.router = router			# this object represents this OR
      self.model = NetworkModel(self.router)	# model for recording link-RTTs
    # Handle testing_mode
    if testing_mode:
      self.filehandler = FileHandler("data/circuits")
    # Init the StreamHandler
    StreamHandler.__init__(self, c, selmgr)    

  def enqueue_pings(self):
    """ To be schedule_immediated by pinger before the first connection is triggered """
    print("\n")
    circs = self.circuits.values()
    for c in circs:
      if c.built:
        # Get id of c
      	id = c.circ_id
        if measure_partial_circs:
	  # If partial measures wanted: get length
	  path_len = len(c.path)
	  for i in xrange(1, path_len):
            self.ping_queue.put((id, i))
            plog("DEBUG", "Enqueued circuit " + str(id) + " hop " + str(i))
	# And for the whole circuit ...
        self.ping_queue.put((id, None))
        plog("DEBUG", "Enqueued circuit " + str(id) + " hop None")
 
  def compute_link_RTTs(self):
    """ Get the circs and check if we can compute RTTs of single links and store these in the model """    
    circs = self.circuits.values()
    # Measure also the duration
    start = time.time()
    for c in circs:
      # Get the length
      path_len = len(c.path)
      # Go through the path
      for i in xrange(1,path_len):
        if i in c.part_rtts:
          # First hop --> add Link from Root to 1
          if i == 1:
	    link_rtt = c.part_rtts[i]
	    self.model.add_link(self.router, c.path[i-1], link_rtt)
	  # Handle i -- (i+1)
          if i+1 in c.part_rtts:
            link_rtt = c.part_rtts[i+1] - c.part_rtts[i]
	    if link_rtt > 0:          
	      plog("INFO", "Computed link-RTT: " + str(link_rtt))
	      # Save to NetworkModel
	      self.model.add_link(c.path[i-1], c.path[i], link_rtt)
	    else:
	      plog("WARN", "Negative link-RTT: " + str(link_rtt))
	  # Handle (n-1) -- n
	  elif None in c.part_rtts:
            # We have a total value
	    link_rtt = c.part_rtts[None] - c.part_rtts[i]
	    if link_rtt > 0:          
	      plog("INFO", "Computed link-RTT: " + str(link_rtt))
	      # Save to NetworkModel
	      self.model.add_link(c.path[i-1], c.path[i], link_rtt)
	    else:
	      plog("WARN", "Negative link-RTT: " + str(link_rtt))
    plog("DEBUG", "Computation of link-RTTs took us " + str(time.time()-start) + " seconds")
    # Print out the model
    self.model.print_graph()
    self.model.find_circuits()

  def attach_ping(self, stream):
    """ Attach a ping stream to its circuit """
    if self.ping_queue.empty():
      # This round has finished
      plog("INFO", "Queue is empty --> round finished, closing stream " + str(stream.strm_id))
      self.c.close_stream(stream.strm_id, 5)
      # Fire the event
      finished_event.set()
      # Call the rest from here?
      self.print_circuits()
      if measure_partial_circs:
        self.compute_link_RTTs()
      return
    else:
      # Get the info and extract
      ping_info = self.ping_queue.get()
      circ_id = ping_info[0]
      hop = ping_info[1]
      # Set circ to stream
      stream.circ = circ_id
      try:
        # Get the circuit 
        if circ_id in self.circuits:
          circ = self.circuits[circ_id]
          if circ.built and not circ.closed:        
            stream.hop = hop
	    self.c.attach_stream(stream.strm_id, circ.circ_id, hop)
            # Don't use pending for pings
          else:
            plog("WARN", "Circuit not built or closed")
	    self.attach_ping(stream)
        else:
          # Go to next test if circuit is gone
          plog("WARN", "Circuit " + str(circ_id) + " does not exist anymore --> passing")
          self.attach_ping(stream)
      except TorCtl.ErrorReply, e:
        plog("WARN", "Error attaching stream: " + str(e.args))

  def stream_status_event(self, s):
    """ Separate Pings from regular streams directly """
    if not (s.target_host == ping_dummy_host and s.target_port == ping_dummy_port):
      # This is no ping, call the other method
      return StreamHandler.stream_status_event(self, s)
    
    # Construct debugging output
    output = [s.event_name, str(s.strm_id), s.status, str(s.circ_id), s.target_host, str(s.target_port)]
    if s.reason: output.append("REASON=" + s.reason)
    if s.remote_reason: output.append("REMOTE_REASON=" + s.remote_reason)
    plog("DEBUG", " ".join(output))
 
    # NEW or NEWRESOLVE
    if s.status == "NEW":
      # Set up the stream object
      stream = Stream(s.strm_id, s.target_host, s.target_port, s.status)
      self.streams[s.strm_id] = stream        
      self.attach_ping(stream)

    # SENTCONNECT 
    elif s.status == "SENTCONNECT":
      # Measure here, means save arrived_at in the dict
      self.start_times[(s.circ_id, self.streams[s.strm_id].hop)] = s.arrived_at
  
    # DETACHED (CLOSED + TORPROTOCOL is also ping, some routers send it when measuring 1-hop)
    elif s.status == "DETACHED" or (s.status == "CLOSED" and s.remote_reason == "TORPROTOCOL"):
      if (s.reason == "TIMEOUT"):
        self.circuits[s.circ_id].timeout_counter += 1
	self.circuits[s.circ_id].slowness_counter += 1
	plog("DEBUG", str(self.circuits[s.circ_id].timeout_counter) + " timeout(s) on circuit " + str(s.circ_id))
	if self.circuits[s.circ_id].timeout_counter >= timeout_limit and not self.circuits[s.circ_id].closed:
	  # Close the circuit
	  plog("DEBUG", "Reached limit on timeouts --> closing circuit " + str(s.circ_id))
	  self.circuits[s.circ_id].closed = True
	  try: self.c.close_circuit(s.circ_id)
	  except TorCtl.ErrorReply, e: 
	    plog("ERROR", "Failed closing circuit " + str(s.circ_id) + ": " + str(e))	    
	# Set RTT for circ to None
	self.circuits[s.circ_id].current_rtt = None
      
      else:
        # No timeout, this is a successful ping: measure here	  
        hop = self.streams[s.strm_id].hop
        # Compute RTT using arrived_at 
        rtt = s.arrived_at - self.start_times[(s.circ_id, hop)]
        plog("INFO", "Measured RTT: " + str(rtt) + " sec")
        # Save RTT to circuit
        self.circuits[s.circ_id].part_rtts[hop] = rtt

        if hop == None:
          # This is a total circuit measuring
	  self.circuits[s.circ_id].add_rtt(rtt)
	  plog("DEBUG", "Added RTT to history: " + str(self.circuits[s.circ_id].stats.values))
	  
	  # Close if num_tests is reached          
	  if testing_mode:
	    if self.circuits[s.circ_id].age >= num_tests:
	      plog("DEBUG", "Closing circ " + str(s.circ_id) + ": num_tests is reached")
	      self.circuits[s.circ_id].closed = True
	      # Save stats to a file in for generating plots etc.
	      self.filehandler.write(str(self.circuits[s.circ_id].stats.mean) + "\t" + str(self.circuits[s.circ_id].stats.dev))
	      self.c.close_circuit(s.circ_id)

	  # Close if slow-max is reached on mean RTT
          if self.circuits[s.circ_id].stats.mean >= slow:
	    self.circuits[s.circ_id].slowness_counter += 1
	    if self.circuits[s.circ_id].slowness_counter >= slowness_limit and not self.circuits[s.circ_id].closed:
	      plog("DEBUG", "Slow-max (" + str(slowness_limit) + ") is reached --> closing circuit " + str(s.circ_id))
	      self.circuits[s.circ_id].closed = True
	      self.c.close_circuit(s.circ_id)

          # Resort only if this is for the complete circ
          self.refresh_sorted_list()

      if s.status == "CLOSED":
        # Stream is gone .. we have to create a new ping :(
        t = threading.Thread(None, self.pinger.ping, "Ping")
	t.setDaemon(True)
	t.start()
	return

      # Call attach ping here and use only one stream for all tests
      self.attach_ping(self.streams[s.strm_id])
      return

######################################### BEGIN: Pinger            #####################

class Pinger(threading.Thread):
  """ Separate thread that triggers the Socks4-connections for pings """
  def __init__(self, ping_handler):
    self.handler = ping_handler		# the PingHandler
    threading.Thread.__init__(self)	# call the thread-constructor
  
  def run(self):
    """ The run()-method """
    while self.isAlive():
      time.sleep(sleep_interval)
      self.do_work()

  def do_work(self):
    """ Do the work """
    # Event is only needed, because some routers close our connection if trying 
    # to use them as one-hop, so we need to create a new connection sometimes and
    # cannot rely on the failing of our first connection
    finished_event.clear()
    # Let all circs to test be enqueued 
    self.handler.schedule_immediate(lambda x: x.enqueue_pings())
    # Simply trigger only _one_ connection
    self.ping()
    finished_event.wait()
  
  # No "try .. except .. finally .." in Python < 2.5 !
  def ping(self):
    """ Create a connection to dummy_host/_port using Socks4 """
    s = None
    try:
      try:
        s = socks.socksocket()
        s.setproxy(socks.PROXY_TYPE_SOCKS4, socks_host, socks_port)
        s.connect((ping_dummy_host, ping_dummy_port))
      except socks.Socks4Error, e:
	# Don't do nothing, this will actually happen
	# print("Got Exception: " + str(e))
	pass
    finally:
      # Close the socket if open
      if s: s.close()

######################################### END: Pinger              #####################

def connect(control_host, control_port):
  """ Return a connection to Tor's control port """
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((control_host, control_port))
  return Connection(sock)
 
def setup_location(conn):
  """ Setup a router object representing this proxy """
  global path_config
  plog("INFO","Setting up our location")
  ip = 0
  # Try to get our IP from Tor
  try:
    info = conn.get_info("address")
    ip = info["address"]
  except: 
    plog("ERROR", "Could not get our IP")
  # Set up a router object
  router = GeoIPSupport.GeoIPRouter(TorCtl.Router(None,"ROOT",None,False,None,None,ip,None,None))
  plog("INFO", "Our IP address is " + router.get_ip_dotted() + " [" + router.country_code + "]")
  # To be configured
  path_config.src_country = router.country_code
  return router
 
def configure(conn):
  """ Set events and options """
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
  # Setup a router instance here
  router = setup_location(conn)
  # Configure myself  
  configure(conn)
  # Set Handler to the connection
  if measure_circs:
    handler = PingHandler(conn, __selmgr, router)
  else:
    handler = StreamHandler(conn, __selmgr)
  conn.set_event_handler(handler)
  # Go to sleep to be able to get killed from the commandline
  try:
    while True:
      time.sleep(60)
  except KeyboardInterrupt:
    cleanup(conn)

def cleanup(conn):
  """ To be called on exit """
  plog("INFO", "Cleaning up...")
  conn.set_option("__LeaveStreamsUnattached", "0")
  conn.set_option("__DisablePredictedCircuits", "0")
  conn.close()

if __name__ == '__main__':
  # Call main
  startup(sys.argv)
