#!/usr/bin/python

"""
  RWTH Aachen University, Informatik IV
  Copyright (C) 2007 Johannes Renner 
  Contact: renner <AT> i4.informatik.rwth-aachen.de
"""

import os
import re
import sys
import copy
import math
import time
import random
import socket
import threading
import Queue
import ConfigParser

from TorCtl import *
from TorCtl.TorUtil import plog, sort_list

## CONFIGURATION ##############################################################

# Set the version
VERSION = "0.0.01-alpha"
# Path to data-directory
DATADIR = "data/op-addon/"
# Our IP-address
IP = None

# Try to get the config-file from the commandline
if len(sys.argv) == 1:
  CONFIG_FILE = "pathrc.example"
elif len(sys.argv) == 2:
  CONFIG_FILE = sys.argv[1]
else: 
  plog("ERROR", "Too many arguments, exiting.")
  sys.exit(0)

# Set some defaults for string-variables that can be None
string_defaults = {"use_exit":None, "entry_country":None, "exit_country":None}
config = ConfigParser.SafeConfigParser(string_defaults)
if os.path.exists(CONFIG_FILE):
  plog("INFO", "Loading configuration from '" + CONFIG_FILE + "'")
  config.read(CONFIG_FILE)
else:
  plog("ERROR", "Config file '" + CONFIG_FILE + "' does not exist, exiting.")
  sys.exit(0)
  
# Sections
HOST_PORT = "HOST_PORT"
CIRC_MANAGEMENT = "CIRC_MANAGEMENT"
NODE_SELECTION = "NODE_SELECTION"
GEOIP = "GEOIP"
TESTING = "TESTING"
RTT = "RTT"
MODEL = "MODEL"

# Measure the circuits
measure_circs = config.getboolean(RTT, "measure_circs")
if measure_circs:
  import socks  
  # Hosts and ports to use for ping streams
  socks_host = config.get(RTT, "socks_host")
  socks_port = config.getint(RTT, "socks_port")
  # Choose randomly from a set of hosts/ports?
  ping_dummy_host = config.get(RTT, "ping_dummy_host")
  ping_dummy_port = config.getint(RTT, "ping_dummy_port")
  # Sleep interval between working loads in sec
  initial_interval = config.getfloat(RTT, "initial_interval")
  frequency = config.getfloat(RTT, "frequency")
  # Close a circ after n timeouts
  timeout_limit = config.getint(RTT, "timeout_limit")
  
  # Set to True if we want to measure partial circuits
  # This also enables circuit creation from the model
  network_model = config.getboolean(MODEL, "network_model")
  if network_model:
    import networkx
    # RTT-threshhold when creating circs from the model
    max_rtt = config.getfloat(MODEL, "max_rtt")    
    # Minimum number of proposals to choose from
    min_proposals = config.getint(MODEL, "min_proposals")
    # Min ratio of traditionally created circs
    # ensures growing of the explored subnet
    min_ratio = config.getfloat(MODEL, "min_ratio")

  # Testing mode: Collect latencies of circuits and links in the 
  # network. Close circuits after num_xx_tests measures and involve 
  # a FileHandler to write data to a file
  TESTING_MODE = config.getboolean(TESTING, "testing_mode")
  if TESTING_MODE:
    # TODO: num_bw_tests = config.getint(TESTING, "num_bw_tests")
    num_rtt_tests = config.getint(TESTING, "num_rtt_tests")
    num_records = config.getint(TESTING, "num_records")

def get_geoip_config():
  """ Read the geoip-configuration from the config-file """
  # Check for GeoIP
  if config.getboolean(GEOIP, "use_geoip"):
    # Optional options
    unique_countries = None
    max_crossings = None
    if config.has_option(GEOIP, "unique_countries"):
      unique_countries = config.getboolean(GEOIP, "unique_countries")
    if config.has_option(GEOIP, "max_crossings"):
      max_crossings = config.getint(GEOIP, "max_crossings")
    path_config = GeoIPSupport.GeoIPConfig(
       unique_countries,
       max_crossings,
       entry_country = config.get(GEOIP, "entry_country"),
       exit_country = config.get(GEOIP, "exit_country"),
       excludes = None)
  else: path_config = None
  return path_config

# Configure the SelectionManager here!!
# Do NOT modify this object directly after it is handed to 
# PathBuilder, Use PathBuilder.schedule_selmgr instead.
__selmgr = PathSupport.SelectionManager(
      pathlen= config.getint(NODE_SELECTION, "pathlen"),
      order_exits = config.getboolean(NODE_SELECTION, "order_exits"),
      percent_fast = config.getint(NODE_SELECTION, "percent_fast"),
      percent_skip = config.getint(NODE_SELECTION, "percent_skip"),
      min_bw = config.getint(NODE_SELECTION, "min_bw"),
      use_all_exits = config.getboolean(NODE_SELECTION, "use_all_exits"),
      uniform = config.getboolean(NODE_SELECTION, "uniform"),
      use_exit = config.get(NODE_SELECTION, "use_exit"),
      use_guards = config.getboolean(NODE_SELECTION, "use_guards"),
      geoip_config = get_geoip_config())

## Connection #################################################################

class Connection(TorCtl.Connection):
  """ Connection-class that uses the RTTCircuit-class 
      TODO: add the CircuitClass to be used somewhere """
  def build_circuit(self, pathlen, path_sel):
    circ = Circuit()
    circ.path = path_sel.build_path(pathlen)
    circ.exit = circ.path[pathlen-1]
    circ.circ_id = self.extend_circuit(0, circ.id_path())
    return circ

  def build_circuit_from_path(self, path):
    """ Build circuit using a given path (= router-objects), 
        used to build circs from NetworkModel """
    circ = Circuit()
    circ.path = path
    circ.exit = path[len(path)-1]
    circ.circ_id = self.extend_circuit(0, circ.id_path())
    return circ

## Stats ######################################################################

class Stats:
  """ Statistics class that is used for recording stats """
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
      values = copy.copy(self.values)
      values.sort()
      return values[(len(values)-1)/2]
    else: return 0.0

## CircuitBuildingStats #######################################################

class CircuitBuildingStats(Stats):
  """ Create an instance of this and gather overall circuit stats """
  def __init__(self):
    Stats.__init__(self)
    self.failures_buildup = 0      # Failures during buildup
    self.failures_established = 0  # Failures on established

  def to_string(self):
    """ Create a string for writing to a file """
    s = "Successful circuit buildups: "
    s += str(len(self.values)) + " records, median=" + str(self.median)
    s += " s, avg=" + str(self.mean) + " s" 
    s += ", dev=" + str(self.dev) + " s (min=" + str(self.min)
    s += " s, max=" + str(self.max) + " s)\n"
    s += "Failures during circuit-buildups: " + str(self.failures_buildup) + "\n"
    s += "Failures on established circuits: " + str(self.failures_established)
    return s

## FileHandler ################################################################

class FileHandler:
  """ FileHandler class for writing/appending collected data to a file """
  def __init__(self, filename):
    self.filename = filename

  def write(self, line):
    self.filehandle = open(self.filename, 'w')
    self.filehandle.write(line + "\n")
    self.filehandle.close() 

  def append(self, line):
    self.filehandle = open(self.filename, 'a')
    self.filehandle.write(line + "\n")
    self.filehandle.close() 
 
  def get_line_count(self):
    self.filehandle = open(self.filename)
    lines = self.filehandle.readlines()
    return len(lines)

## Circuit & Stream ###########################################################

class Circuit(PathSupport.Circuit): 
  """ Circuit class extended to RTTs and related stats """
  def __init__(self):
    PathSupport.Circuit.__init__(self)
    # RTT stuff
    self.part_rtts = {}		# Dict of partial rtts, pathlen 3: 1-2-None
    self.current_rtt = None	# Double (sec): current value
    self.stats = Stats()	# Stats about total RTT contains history
    # Counters and flags
    self.age = 0		# Age in rounds
    self.timeout_counter = 0	# Timeout limit
    self.rtt_created = False	# Created from the model    
  
  def add_rtt(self, rtt):
    """ Add a new value and refresh stats and current """
    # Set current
    if self.current_rtt == None:
      self.current_rtt = rtt
    else:
      self.current_rtt = (self.current_rtt * 0.5) + (rtt * 0.5)
      plog("DEBUG", "Computing new current RTT from " + str(rtt) + " to " + 
         str(self.current_rtt))
    # Add new RTT to the stats
    self.stats.add_value(rtt)
    # Increase age
    self.age += 1

  def to_string(self):
    """ Create a current string representation """
    s = "Circuit " + str(self.circ_id) + ": "
    for r in self.path: s += " " + r.nickname + "(" + str(r.country_code) + ")"
    if not self.built: s += " (not yet built)"
    else: s += " (age=" + str(self.age) + ")"
    if self.current_rtt: 
      s += ": " "RTT [current (median/mean/dev)]: "
      s += str(self.current_rtt) + " (" + str(self.stats.median) + "/"
      s += str(self.stats.mean) + "/" + str(self.stats.dev) + ")"
    if self.rtt_created: s += "*"
    return s

class Stream(PathSupport.Stream):
  """ Stream class extended to hop """
  def __init__(self, sid, host, port, kind):
    PathSupport.Stream.__init__(self, sid, host, port, kind)
    self.hop = None	# Save hop if this is a ping, hop=None is complete circ

## NetworkModel ###############################################################

class LinkInfo:
  """ This class contains infos about a link: source, destination, RTT
      plus: rtt_history, methods to compute stats, etc. """
  def __init__(self, src, dest, rtt=0):
    # Set src and dest
    self.src = src
    self.dest = dest
    # The current value
    self.current_rtt = None
    # Set the RTT
    self.add_rtt(rtt)

  def add_rtt(self, rtt):
    # Compute new current value from the last
    if self.current_rtt == None: self.current_rtt = rtt
    else: 
      self.current_rtt = (self.current_rtt * 0.5) + (rtt * 0.5)
      plog("DEBUG", "Computing new current RTT from " + str(rtt) + " to " + 
         str(self.current_rtt))

class PathProposal:
  """ Instances of this class are path-proposals found in the model """
  def __init__(self, links, path):
    # This is a list of LinkInfo objects
    self.links = links
    # Cut off ROOT here
    self.path = path[1:len(path)]
    # Compute the expected RTT
    self.rtt = reduce(lambda x,y: x + y.current_rtt, self.links, 0.0)
    self.min_bw = 0             # Minimum bw of routers in the path
    self.ranking_index = None   # Score computed from bw and RTT

  def to_string(self):
    """ Create a string for printing out information """
    s = ""
    for l in self.links:
      s += str(l.src) + "--" + l.dest + " (" + str(l.current_rtt) + ") " + ", "
    return s + "--> " + str(self.rtt) + " sec" 

class NetworkModel:  
  """ This class is used to record measured RTTs of single links in a model 
      of the 'currently explored subnet' (undirected graph) """  
  def __init__(self, routers):
    """ Constructor: pass the root of all circuits """
    self.pickle_path = DATADIR + "network-model.pickle"
    self.logfile = None         # FileHandler(DATADIR + "proposals")
    # For generating proposals
    self.proposals = []         # Current list of circ-proposals
    self.prefixes = {}          # Prefixes for DFS
    self.routers = routers      # Link to the router-list
    self.target_host = None
    self.target_port = None
    self.max_rtt = 0
    try:
      self.graph = self.load_graph()
      self.up_to_date = False
    except:
      plog("INFO", "Could not load a model, creating a new one ..")
      self.graph = networkx.XGraph(name="Explored Tor Subnet")
      self.graph.add_node(None)
      self.up_to_date = True
    self.print_info()
    plog("INFO", "NetworkModel initiated")

  def save_graph(self):
    """ Write the graph to a binary file """
    start = time.time()
    networkx.write_gpickle(self.graph, self.pickle_path)
    plog("INFO", "Saved network-model to '" + self.pickle_path +
       "' in " + str(time.time()-start) + " sec")

  def load_graph(self):
    """ Load a graph from a binary file and return it """
    graph = networkx.read_gpickle(self.pickle_path)    
    plog("INFO", "Loaded graph from '" + self.pickle_path + "'")
    return graph
   
  def add_link(self, src, dest, rtt):
    """ Add link to the graph given src, dest (router-ids) & RTT (LinkInfo) """
    self.graph.add_edge(src, dest, LinkInfo(src, dest, rtt))
 
  def add_circuit(self, c):
    """ Check if we can compute RTTs of single links for a circuit 
        and store these in the model """
    # Get the length
    path_len = len(c.path)
    # Go through the path
    for i in xrange(1,path_len):
      if i in c.part_rtts:
        # First hop --> add Link from Root to 1
        if i == 1:
	  link_rtt = c.part_rtts[i]
	  self.add_link(None, c.path[i-1].idhex, link_rtt)
	# Handle i -- (i+1)
        if i+1 in c.part_rtts:
          link_rtt = c.part_rtts[i+1] - c.part_rtts[i]
	  if link_rtt > 0:          
	    plog("INFO", "Computed link-RTT " + str(i) + ": " + str(link_rtt))
	    self.add_link(c.path[i-1].idhex, c.path[i].idhex, link_rtt)
	  else:
	    plog("WARN", "Negative link-RTT " + str(i) + ": " + str(link_rtt))
	# Handle (n-1) -- n
	elif None in c.part_rtts:
          # We have a total value
	  link_rtt = c.part_rtts[None] - c.part_rtts[i]
	  if link_rtt > 0:          
	    plog("INFO", "Computed link-RTT " + str(i) + ": " + str(link_rtt))
	    self.add_link(c.path[i-1].idhex, c.path[i].idhex, link_rtt)
	  else:
	    plog("WARN", "Negative link-RTT " + str(i) + ": " + str(link_rtt))
      self.up_to_date = False

  def delete_node(self, idhex):
    """ Delete a router from the model """
    if idhex in self.graph:
      # Delete links first
      edges = self.graph.edge_boundary(idhex)
      for e in edges:
        self.graph.delete_edge(e)
      # Then remove the node
      self.graph.delete_node(idhex)
      plog("INFO", "Deleted node with ID " + idhex + " from the model")
      self.up_to_date = False

  def update(self):
    """ Update model with a given list of routers """
    nodes = self.graph.nodes()
    for id in nodes:
      if not id in self.routers:
        if id:
          plog("INFO", "Router with id " + id + 
             " is not known, deleting node ..")
          self.delete_node(id)
    plog("INFO", "Updated model with current router-list")

  def set_target(self, host, port, max_rtt=0):
    """ Change the target for generating paths """
    if self.target_host != host or self.target_port != port\
       or self.max_rtt != max_rtt:
      self.target_host = host
      self.target_port = port
      self.max_rtt = max_rtt
      self.up_to_date = False

  def generate_proposals(self):
    """ Call visit() on the root-node """
    self.update()
    # Reset list of proposals and prefixes for DFS
    self.proposals = []
    self.prefixes.clear()
    start = time.time()
    # Start the search
    self.visit(None, [])
    self.up_to_date = True
    plog("INFO", "Generating " + str(len(self.proposals)) + 
      " proposals took us " + str(time.time()-start) + 
      " seconds [max_rtt=" + str(self.max_rtt) + "]")

  def get_link_info(self, path):
    """ From a path given as list of ids, return link-infos """
    links = []
    for i in xrange(0, len(path)-1):
      links.append(self.graph.get_edge(path[i], path[i+1]))
    return links

  def visit(self, node, path, i=1):
    """ Recursive Depth-First-Search: Maybe use some existing methods """
    if node not in path:
      path.append(node)
      # Root -- Exit
      if len(path) == 4:
        # This could be an option
        if "Exit" in self.routers[node].flags:
          if self.routers[node].will_exit_to(self.target_host, self.target_port):
            p = PathProposal(self.get_link_info(path), path) 
            if self.max_rtt > 0:
              if p.rtt <= self.max_rtt:
                self.proposals.append(p)
            else: self.proposals.append(p)
      else:
        self.prefixes[i] = path
	# The graph is also a dict
        for n in self.graph[node]:
	  if n not in self.prefixes[i]:
	    self.visit(n, copy.copy(self.prefixes[i]), i+1)

  def print_info(self):
    """ Create a string holding info and the proposals for printing """
    out = str(self.graph.info())
    for p in self.proposals:
      out += "\nProposal: " + p.to_string()    
    # Only print them out if there are not too much
    if len(self.proposals) > 50: 
      plog("INFO", "Currently " + str(len(self.proposals)) + 
         " proposals! Not printing them out ..")
    else:
      print(out)
    # Log all of them to the file if it exists
    if self.logfile: self.logfile.write(out)

## PingHandler ################################################################

class PingHandler(PathSupport.StreamHandler):
  """ This class extends the general StreamHandler to handle ping-requests """
  def __init__(self, c, selmgr, num_circs, RouterClass, use_model=False):
    # Loggers for recording statistics
    self.circ_stats = CircuitBuildingStats()    # record setup-durations
    self.stats_logger = FileHandler(DATADIR + "circ-setup-stats")
    self.setup_logger = None # FileHandler(DATADIR + "circ-setup-durations")
    if TESTING_MODE:
      self.latency_logger = FileHandler(DATADIR + "mean-latencies")

    # Queue containing circs to be tested
    self.ping_queue = Queue.Queue()	# (circ_id, hop)-pairs

    if use_model:
      PathSupport.StreamHandler.__init__(self, c, selmgr, 0, RouterClass)
      self.model = NetworkModel(self.routers)
      self.num_circuits = num_circs
      self.check_circuit_pool()
    else:
      self.model = None
      PathSupport.StreamHandler.__init__(self, c, selmgr, num_circs, RouterClass)

    # Sorted circuit list
    self.sorted_circs = []
    # Start the Pinger
    self.pinger = Pinger(self)
    self.pinger.setDaemon(True)
    self.pinger.start()

  def refresh_sorted_list(self):
    """ Sort the list for their current RTTs """
    def notlambda(x): 
      # If not measured yet, return a max value
      if x.current_rtt == None: return 10
      else: return x.current_rtt
    self.sorted_circs = sort_list(self.circuits.values(), notlambda)
    plog("DEBUG", "Refreshed sorted list of circuits")

  def print_circuits(self, list=None):
    """ Print out the circuits + some info, optionally pass a (sorted) list """
    if list: circs = list
    else: circs = self.circuits.values()
    plog("INFO", "We have " + str(len(circs)) + " circuits:")
    for c in circs:
      print("+ " + c.to_string())
  
  def log_circuit(self, circ):
    """ Only called in TESTING_MODE when tests are finished for writing 
        any interesting values to a file before closing a circ """
    self.latency_logger.append(str(circ.setup_duration) + "\t" + 
       "\t" + str(circ.stats.mean))
    line_count = self.latency_logger.get_line_count()
    if line_count >= num_records:
      plog("INFO", "Enough records, exiting. (line_count = " + 
         str(line_count) + ")")
      # TODO: How to kill the main thread from here?
      sys.exit(1)

  def enqueue_pings(self):
    """ schedule_immediate from pinger before triggering the initial ping """
    print("")
    self.refresh_sorted_list()
    # TODO: Check if there are any circs, else let the Pinger wait?
    circs = self.circuits.values()
    for c in circs:
      if c.built:
        # Get id of c
      	id = c.circ_id
        if self.model:
	  # Enqueue every hop
	  path_len = len(c.path)
	  for i in xrange(1, path_len):
            self.ping_queue.put((id, i))
            plog("DEBUG", "Enqueued circuit " + str(id) + " hop " + str(i))
	# And for the whole circuit ...
        self.ping_queue.put((id, None))
        plog("DEBUG", "Enqueued circuit " + str(id) + " hop None")

  def attach_ping(self, stream):
    """ Attach a ping stream to its circuit """
    if self.ping_queue.empty():
      # This round has finished
      plog("INFO", "Queue is empty --> round has finished, closing stream " 
         + str(stream.strm_id))
      self.close_stream(stream.strm_id, 5)
      # Print information
      self.print_circuits(self.sorted_circs)      
      if self.model:
        self.model.print_info()
      # Enqueue again all circs
      self.enqueue_pings()

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
          # Go to next test if circuit is gone or we get an ErrorReply
          plog("WARN", "Circuit " + str(circ_id) + 
             " does not exist anymore --> passing")
          self.attach_ping(stream)
      except TorCtl.ErrorReply, e:
        plog("WARN", "Error attaching stream " + str(stream.strm_id) + 
           " :" + str(e.args))
	self.attach_ping(stream)

  def record_ping(self, s):
    """ Record a ping from a stream event (DETACHED or CLOSED) """
    # No timeout, this is a successful ping: measure here	  
    hop = self.streams[s.strm_id].hop
    rtt = s.arrived_at-self.streams[s.strm_id].attached_at
    plog("INFO", "Measured RTT: " + str(rtt) + " sec")
    # Save RTT to circuit
    self.circuits[s.circ_id].part_rtts[hop] = rtt
    if hop == None:
      # This is a total circuit measuring
      self.circuits[s.circ_id].add_rtt(rtt)
      plog("DEBUG", "Added RTT to history: " + 
         str(self.circuits[s.circ_id].stats.values))	  
      
      # TESTING_MODE: close if num_rtt_tests is reached  
      if TESTING_MODE:
        if self.circuits[s.circ_id].age == num_rtt_tests:
          plog("DEBUG", "Closing circ " + str(s.circ_id) + 
             ": num_rtt_tests is reached")
          # Save stats to a file for generating plots etc.
          if self.model:
	    if self.circuits[s.circ_id].rtt_created:
              self.log_circuit(self.circuits[s.circ_id])
          else:
            self.log_circuit(self.circuits[s.circ_id])
          # Close the circuit
          self.close_circuit(s.circ_id)
      
      # Resort only if this is for the complete circ
      self.refresh_sorted_list()
      if self.model:
        # Add the links of this circuit to the model
        self.model.add_circuit(self.circuits[s.circ_id])

  def stream_status_event(self, s):
    """ Separate pings from regular streams directly """
    if not (s.target_host == ping_dummy_host and 
       s.target_port == ping_dummy_port):
      # This is no ping, call the other method
      return PathSupport.StreamHandler.stream_status_event(self, s)
    
    # Construct debugging output
    output = [s.event_name, str(s.strm_id), s.status, str(s.circ_id), 
       s.target_host, str(s.target_port)]
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
      # Measure here, means set attached_at on the stream
      self.streams[s.strm_id].attached_at = s.arrived_at
  
    # DETACHED
    elif s.status == "DETACHED":      
      if (s.reason == "TIMEOUT"):
        self.circuits[s.circ_id].timeout_counter += 1
        plog("DEBUG", str(self.circuits[s.circ_id].timeout_counter) + 
           " timeout(s) on circuit " + str(s.circ_id))
        if timeout_limit > 0:
          if self.circuits[s.circ_id].timeout_counter >= timeout_limit and not self.circuits[s.circ_id].closed:
            # Close the circuit
            plog("DEBUG", "Reached limit on timeouts --> closing circuit " 
               + str(s.circ_id))
            self.close_circuit(s.circ_id)
        # Set RTT for this circ to None
        self.circuits[s.circ_id].current_rtt = None
      else:
        # No timeout: Record the result
        self.record_ping(s)              
      # Close the stream
      self.close_stream(s.strm_id, 5)

    # CLOSED + END is also ping, some routers send it when measuring
    # latency to a single hop, better measure on FAILED?
    elif s.status == "CLOSED":
      if s.reason == "END":
        # Only record
        self.record_ping(s)

  def circ_status_event(self, c):
    """ Override to record statistics on circuit-setups and -failures """
    if c.circ_id not in self.circuits:
      return PathSupport.CircuitHandler.circ_status_event(self, c)    
    
    # Catch FAILED/CLOSED now since circ will be removed
    elif c.status == "FAILED" or c.status == "CLOSED":
      circ = self.circuits[c.circ_id]
      # Setup a message for logging
      message = ["FAILED"]
      if c.reason: message.append("REASON=" + c.reason)
      if c.remote_reason: message.append("REMOTE_REASON=" + c.remote_reason)
      if not circ.built:
        if self.setup_logger:
          self.setup_logger.append(" ".join(message) + ": " + 
             str(circ.extend_times))
        # Increase counter and write circ_stats to file
        if self.model:
          if circ.rtt_created:
            self.circ_stats.failures_buildup += 1
            self.stats_logger.write(self.circ_stats.to_string()) 
        else:
          self.circ_stats.failures_buildup += 1
          self.stats_logger.write(self.circ_stats.to_string())
      elif not c.reason == "REQUESTED":
        # Increase *other* counter and write stats to file
        if self.model:
          if circ.rtt_created:
            self.circ_stats.failures_established += 1
            self.stats_logger.write(self.circ_stats.to_string()) 
        else:
          self.circ_stats.failures_established += 1
          self.stats_logger.write(self.circ_stats.to_string())

    # Call the underlying method in any case
    PathSupport.CircuitHandler.circ_status_event(self, c)
    
    if c.status == "FAILED" or c.status == "CLOSED":
      self.refresh_sorted_list()
    # Log something on BUILT
    if c.status == "BUILT":
      circ = self.circuits[c.circ_id]
      if self.setup_logger:
        self.setup_logger.append(str(circ.extend_times))    
      # Add duration to circ_stats and write file
      if self.model:
        if circ.rtt_created:
          self.circ_stats.add_value(circ.setup_duration)
          self.stats_logger.write(self.circ_stats.to_string())
      else:
        self.circ_stats.add_value(circ.setup_duration)
        self.stats_logger.write(self.circ_stats.to_string())
      self.refresh_sorted_list()
   
  def build_circuit(self, host, port):
    """ Override from CircuitHandler to support circuit-creation from model """
    if self.model:
      circ = None
      # This is to ensure expansion of the model:
      # Check ratio if we would add circ from model
      trad = self.get_trad_circs()
      ratio = trad/(len(self.circuits.values())+1.)
      plog("DEBUG","Expected Ratio = " + str(ratio) + 
         " >= " + str(min_ratio) + " ?")
      if ratio >= min_ratio:
        if self.create_circ_from_model(host, port):
	  return
        plog("INFO", "Not enough proposals [min_proposals=" + str(min_proposals) + "]")
 
    # Create a circuit with the backup-method
    plog("DEBUG", "Creating circuit with the backup-method")
    PathSupport.CircuitHandler.build_circuit(self, host, port)

  # Path selection from the model =============================================
  def create_circ_from_model(self, host, port):
    # Set the target
    self.model.set_target(host, port, max_rtt)
    if not self.model.up_to_date:
      self.model.generate_proposals()
    # Get the proposals and compute ranking
    proposals = self.model.proposals
    if len(proposals) >= min_proposals:
      self.update_ranking(proposals)
    # As long as there are enough
    while len(proposals) >= min_proposals:

      # Uniform:
      # choice = random.choice(proposals)            
      
      # Fastest First:
      # proposals = sort_list(proposals, lambda x: x.rtt)
      # choice = proposals[0]            
          
      # Probabilistic:
      choice = self.weighted_selection(proposals, lambda x: x.ranking_index)

      # Convert ids to routers
      r_path = self.keys_to_routers(choice.path)
      if r_path and self.path_is_ok(r_path, host, port):
        plog("INFO", "Chosen proposal: " + choice.to_string())
        try:
          circ = self.c.build_circuit_from_path(r_path)
          circ.rtt_created = True
          self.circuits[circ.circ_id] = circ
	  plog("INFO", "Created circ from model: " + str(circ.circ_id))
          return True
        except TorCtl.ErrorReply, e:
          plog("NOTICE", "Error building circuit: " + str(e.args))
      else:
        proposals.remove(choice)
  
  def weighted_selection(self, proposals, weight):
    """ Select a proposal in a probabilistic way """
    choice = None
    # Compute the sum of weights
    sum = 0
    for p in proposals:
      sum += weight(p)
    plog("DEBUG", "Sum of all weights is " + str(sum))
    # Choose a random number from [0,sum-1]
    i = random.randint(0, sum-1)
    plog("DEBUG", "Chosen random number is " + str(i))
     # Go through the proposals and subtract
    for p in proposals:
      i -= weight(p)
      if i < 0:
        choice = p
        plog("DEBUG", "Chosen path with ranking " + 
           str(weight(choice)))
        return choice
  
  def update_ranking(self, proposals):
    """ Compute a ranking for each path-proposal using 
        measured RTTs and bandwidth from the descriptors """
    start = time.time()
    # Set min_bw to proposals
    for p in proposals:
      # Get the routers
      r_path = self.keys_to_routers(p.path)
      if r_path:
        # Find min(bw_i)
        bw = []
        for r in r_path:
          bw.append(r.bw)
        p.min_bw = min(bw)
      else:
        proposals.remove(p)
        plog("DEBUG", "Could not find the routers, removed ..")
    # High bandwidths get high scores
    sort_list(proposals, lambda x: x.min_bw)
    plog("DEBUG", "MIN_BWs of proposals between: " + str(proposals[0].min_bw) + 
       " and " + str(proposals[len(proposals)-1].min_bw))
    i = 1
    for p in proposals:
      p.bw_score = i
      i += 1
    # Low Latencies get high scores
    sort_list(proposals, lambda x: x.rtt)
    plog("DEBUG", "RTTs of proposals between: " + str(proposals[0].rtt) + 
       " and " + str(proposals[len(proposals)-1].rtt))
    i = len(proposals)
    for p in proposals:
      p.rtt_score = i
      i -= 1
    # Compute weights from both of the values
    for p in proposals:
      # Calculate total score
      # TODO: Weight these scores
      total_score = p.rtt_score + p.bw_score
      p.ranking_index = total_score
    sort_list(proposals, lambda x: x.ranking_index)
    plog("DEBUG", "Ranking indices of proposals between: " + 
       str(proposals[0].ranking_index) + " and " + 
       str(proposals[len(proposals)-1].ranking_index))
    plog("INFO", "Updating ranking indices of proposals took " + 
       str(time.time()-start) + " sec")

  # Helper functions ==========================================================
  def established(self, circ_list):
    """ Check if there is at least one circuit established """
    # XXX: Currently NOT used
    for c in circ_list:
      if c.built:
        return True
  
  def get_trad_circs(self):
    """ Count the circuits with rtt_created == False """
    trad_circs = 0
    for c in self.circuits.values():
      if c.rtt_created == False:
        trad_circs += 1
    return trad_circs

  def path_is_ok(self, path, host, port):
    """ Check if there is currently a circuit with the given path (Routers) """
    for c in self.circuits.values():
      if c.path == path:
        plog("ERROR", "Proposed circuit already exists")        
        return False
    return True

  def keys_to_routers(self, keys):
    """ See if we know the routers specified by keys and return them """
    routers = []
    for id in keys:
      if id in self.routers:
        routers.append(self.routers[id])
      else: 
        plog("INFO", "We do not know about a router having ID " + id)
        try:
          self.model.delete_node(id)
        except:
          plog("ERROR", "Could not delete router with ID " + id)
    if len(routers) == len(keys):
      return routers

  def unknown_event(self, event):
    # XXX: There are new events not yet recognized by our classes
    plog("DEBUG", "UNKNOWN EVENT: " + str(event))

## Pinger #####################################################################

class Pinger(threading.Thread):
  """ Separate thread that triggers the Socks4-connections for pings """
  def __init__(self, ping_handler):
    self.handler = ping_handler		# the PingHandler
    threading.Thread.__init__(self)	# call the thread-constructor
  
  def run(self):
    """ The run()-method """
    time.sleep(initial_interval)
    self.handler.schedule_immediate(lambda x: x.enqueue_pings())
    while self.isAlive():
      self.ping()
      time.sleep(frequency)
  
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

## End of Classes #############################################################

def connect(host, port):
  """ Return a connection to Tor's control port """
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((host, port))
  return Connection(sock)
 
def setup_location(conn):
  """ Setup a router object representing this proxy """
  #global path_config
  global IP
  try:
    # Try to determine our IP
    info = conn.get_info("address")
    IP = info["address"]
    # Get the country_code
    country_code = GeoIPSupport.get_country(IP)
    plog("INFO", "Our IP address is " + str(IP) + " [" + str(country_code) + "]")   
  except: 
    plog("WARN", "Could not get our IP and country")
    return False
  # Here we could set the current entry-country
  # path_config.entry_country = country_code
  return True

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
  try:
    # Connect to Tor process
    conn = connect(config.get(HOST_PORT, "control_host"),
       config.getint(HOST_PORT, "control_port"))
    # TODO: Give password here
    conn.authenticate()
    #conn.debug(file("control.log", "w"))
  except socket.error, e:
    plog("ERROR", "Could not connect to Tor process .. running?")
    return
  # Setup our location
  setup_location(conn)
  # Configure myself  
  configure(conn)
  # Get the size of the circuit-pool from config
  num_circs = config.getint(CIRC_MANAGEMENT, "idle_circuits")
  # Set an EventHandler to the connection
  if measure_circs:
    if network_model:
      handler = PingHandler(conn, __selmgr, num_circs, 
         GeoIPSupport.GeoIPRouter, True)
    else:
      handler = PingHandler(conn, __selmgr, num_circs, GeoIPSupport.GeoIPRouter)  
  else:
    # No pings, only a StreamHandler
    handler = PathSupport.StreamHandler(conn, __selmgr, num_circs, 
       GeoIPSupport.GeoIPRouter)
  conn.set_event_handler(handler)
  # Go to sleep to be able to get killed from the commandline
  # TODO: Do this only if *not* in testing_mode?
  try:
    while True:
      time.sleep(60)
  except KeyboardInterrupt:
    # XXX: Schedule this
    if measure_circs:
      if network_model:
        handler.model.save_graph()
    # Stop other threads?
    cleanup(conn)
    sys.exit(1)

def cleanup(conn):
  """ To be called on exit """
  plog("INFO", "Cleaning up...")
  conn.set_option("__LeaveStreamsUnattached", "0")
  conn.set_option("__DisablePredictedCircuits", "0")
  conn.close()

if __name__ == '__main__':
  plog("INFO", "OP-Addon v" + VERSION)
  startup(sys.argv)
