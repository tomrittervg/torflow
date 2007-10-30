#!/usr/bin/python

"""
  RWTH Aachen University, Informatik IV
  Copyright (C) 2007 Johannes Renner 
  Contact: renner@i4.informatik.rwth-aachen.de
"""

# Addon for onion routers:
# Shall provide information about available bandwidth on single 
# TLS-connections as well as globally available bandwidth for 
# requesting clients in an anonymity-preserving way (?).

# TODO: Make the document be served by Tor via HTTP

import re
import sys
import sched
import time
import socket
import atexit
import threading
import traceback

from TorCtl import *
from TorCtl.TorUtil import *

# Set the version here
VERSION = "0.0-alpha"

# Move these to a config file:
# Tor host and port
control_host = "127.0.0.1"
control_port = 9051
# Listen host and port
listen_host = "137.226.12.177"
listen_port = 9053

# Duration of single measuring interval (seconds)
interval = 20

# Alpha for computing new max values, let max
# decrease slowly if no traffic or not topped
alpha = .9999
# Minimum 'available' bandwidth (byte/sec) 
# to show up on the document
available_min = 0

# Global variable marks the start of an interval
start = time.time()
# Overall start time
total_start = time.time()

# Variable that contains the status-document
bw_status = "no status document available yet :(\r\n"

# Dictionary that contains all stats 
stats = {}
stats_lock = threading.Lock()
# Dicts that contain mappings
key_to_name = {}
name_to_key = {}

# We use the same class for recording global stats and link stats
class LinkBandwidthStats(TorCtl.Router):
  def __init__(self, r=None):
    if r:
      self.__dict__ = r.__dict__
    else:
      self.down = 0
    # Total counters
    self.tot_age = 0
    self.tot_count = 0
    self.tot_ncircs = 0
    self.tot_read = 0
    self.tot_written = 0
    self.tot_bytes = 0		# total read + written
    # Interval stats
    self.int_read = 0		# count bytes read & written ..
    self.int_written = 0	# in the last interval
    self.int_bytes = 0 		# sum of both, gets set on update()
    self.curr_throughput = 0.0	# avg throughput for the last interval 
    self.max_throughput = 0.0	# throughput max-value
    self.available = 0.0	# max - avg

  def read(self, bytes_read):
    self.tot_read += bytes_read
    self.int_read += bytes_read

  def written(self, bytes_written):
    self.tot_written += bytes_written
    self.int_written += bytes_written

  # Reset all of the interval counters
  def reset_interval_counters(self):
    self.int_read = 0
    self.int_written = 0
    self.int_bytes = 0

  # Most important method here
  def update(self, elapsed):
    # Compute the interval-bytes read+written
    self.int_bytes = self.int_read + self.int_written
    # Compute total bytes
    self.tot_bytes = self.tot_read + self.tot_written
    # Compute avg interval throughput
    self.curr_throughput = self.int_bytes/elapsed        

    # Max handling ..
    if self.curr_throughput > self.max_throughput:
      # We have a new max!
      self.max_throughput = self.curr_throughput
      plog("DEBUG", self.nickname + " reached new max: " + 
         str(self.max_throughput) + " byte/sec")
    else:
      # Saving old max for debugging only
      old_max = self.max_throughput    
      # Decrease the max-value using alpha-formula 
      self.max_throughput = max(self.curr_throughput, (self.max_throughput*alpha + self.curr_throughput*(1-alpha)))	
      #plog("DEBUG", self.nickname + ": max decreased from " 
      #   + str(old_max) + " to " + str(self.max_throughput))

    # Compute the difference as 'available'
    # TODO: Add the frac part from the approaches 
    self.available = self.max_throughput - self.curr_throughput
    # Reset the counters
    self.reset_interval_counters()

# Special instance of LinkBandwidthStats for recording of bw-events
global_stats = LinkBandwidthStats()
global_stats.nickname = "Global stats"

# We need an EventHandler
# extend from TorCtl.EventHandler
class LinkHandler(TorCtl.EventHandler):
  def __init__(self, conn):
    # Set the connection
    self.c = conn
    TorCtl.EventHandler.__init__(self)

  # Method to handle BW-events for recording total bw
  def bandwidth_event(self, event):
    #plog("NOTICE", "BW-Event: " + str(event.read) + " bytes read, " + str(event.written) + " bytes written")  
    if event.read: global_stats.read(event.read)
    if event.written: global_stats.written(event.written)

  # Method to handle ORCONN-events
  def or_conn_status_event(self, o): 
    # Count all clients as one:
    # If o.endpoint is an idhash
    if re.search(r"^\$", o.endpoint):
      if o.endpoint not in key_to_name:
        o.endpoint = "AllClients:HASH"
      else: o.endpoint = key_to_name[o.endpoint]
    # If it is no idhash and not in name_to_key
    elif o.endpoint not in name_to_key:
      plog("DEBUG", "IP? " + o.endpoint)
      o.endpoint = "AllClients:IP"

    # If NEW, LAUNCHED or CONNECTED
    if o.status == "NEW" or o.status == "LAUNCHED" or o.status == "CONNECTED":
      plog("NOTICE", "Connection to " + o.endpoint + " is now " + o.status)

    # If status is READ or WRITE
    elif o.status == "READ" or o.status == "WRITE":
      #plog("DEBUG", o.endpoint + ", read: " + str(o.read_bytes) + " wrote: " + str(o.wrote_bytes))      
      stats_lock.acquire()
      # If not in stats: add!
      if o.endpoint not in stats:
        stats[o.endpoint] = LinkBandwidthStats()
        stats[o.endpoint].nickname = o.endpoint
        plog("NOTICE", "+ Added " + o.endpoint + " to the stats")
      # Add number of bytes to total and interval
      if o.read_bytes: stats[o.endpoint].read(o.read_bytes)
      if o.wrote_bytes: stats[o.endpoint].written(o.wrote_bytes)
      stats_lock.release()
      
    # If CLOSED or FAILED  
    elif o.status == "CLOSED" or o.status == "FAILED": 
      # Don't record reasons!
      stats_lock.acquire()      
      if o.endpoint not in stats:
	# Add .. if there will be no traffic it will be removed in the next round
        stats[o.endpoint] = LinkBandwidthStats()
        stats[o.endpoint].nickname = o.endpoint
        plog("NOTICE", "+ Added " + o.endpoint + " to the stats")
      # Add 'running' to status
      if o.status == "FAILED" and not stats[o.endpoint].down:
        o.status = o.status + "(Running)"
      # 'Total' stats	
      stats[o.endpoint].tot_ncircs += o.ncircs
      stats[o.endpoint].tot_count += 1
      if o.age: stats[o.endpoint].tot_age += o.age
      #if o.read_bytes: stats[o.endpoint].tot_read += o.read_bytes
      #if o.wrote_bytes: stats[o.endpoint].tot_wrote += o.wrote_bytes      
      stats_lock.release()

      # This is only for constructing debug output
      if o.age: age = "AGE="+str(o.age)
      else: age = ""
      if o.read_bytes: read = "READ="+str(o.read_bytes)
      else: read = ""
      if o.wrote_bytes: wrote = "WRITTEN="+str(o.wrote_bytes)
      else: wrote = ""
      if o.reason: reason = "REASON="+o.reason
      else: reason = ""
      if o.ncircs: ncircs = "NCIRCS="+str(o.ncircs)
      else: ncircs = ""
      plog("DEBUG", " ".join((o.event_name, o.endpoint, o.status, age, read, wrote, reason, ncircs)))

  # NS-EventHandler methods
  def ns_event(self, n):
    read_routers(self.c, n.nslist)
 
  def new_desc_event(self, d):
    for i in d.idlist: # Is this too slow?
      read_routers(self.c, self.c.get_network_status("id/"+i))

# Sort a list by a specified key
def sort_list(list, key):
  list.sort(lambda x,y: cmp(key(y), key(x))) # Python < 2.4 hack
  return list

# Write document to file f
def write_file(f):
  f.write(bw_status)
  f.close()

# Read the routers
def read_routers(c, nslist):
  global key_to_name, name_to_key
  bad_key = 0
  stats_lock.acquire()
  for ns in nslist:
    try:
      key_to_name[ns.idhex] = ns.nickname
      name_to_key[ns.nickname] = ns.idhex
      r = LinkBandwidthStats(c.get_router(ns))
      if ns.nickname in stats:
        if stats[ns.nickname].idhex != r.idhex:
          plog("NOTICE", "Router "+r.nickname+" has multiple keys: "
             +stats[ns.nickname].idhex+" and "+r.idhex)
      stats[r.nickname] = r # XXX: We get names only from ORCONN :(
    except TorCtl.ErrorReply:
      bad_key += 1
      if "Running" in ns.flags:
        plog("INFO", "Running router "+ns.nickname+"="+ns.idhex+" has no descriptor")
      pass
    except:
      traceback.print_exception(*sys.exc_info())
      continue
  stats_lock.release()

# Update stats and reset every router's counters
# (Requires stats_lock.acquire())
def update_stats(elapsed):
  # Update & reset global stats
  global_stats.update(elapsed)
  # Get the links
  links = stats.values()
  for l in links:
    # Update & reset stats
    l.update(elapsed)

# Create the new status document
# (Requires stats_lock.acquire())
# TODO: Somehow compress the data:
#  - if available==max --> only deliver max?
#  - only deliver available?
#  - leave out links with available==0 ? 
#      - No, avail==0 means new max, but not nothing available!
#  - clustering/classification?
def create_document():
  new_status = ""
  # Fill in global_stats
  new_status += str(global_stats.available) + " "
  new_status += str(global_stats.max_throughput) + " "
  new_status += str(global_stats.curr_throughput) + "\r\n"    
  # Sort the document for available
  key = lambda x: x.available
  links_sorted = sort_list(stats.values(), key)  
  for l in links_sorted:
    # Cutoff at available_min
    if key(l) >= available_min and l.nickname != "AllClients:HASH":
      new_status += l.nickname + " " + str(key(l)) + " "      
      new_status += str(l.max_throughput) + " " + str(l.curr_throughput) + "\r\n"      
  # Critical: Exchange global bw_status document
  global bw_status
  bw_status = new_status

# This is the method where the main work is done
# Schedule the call every 'interval' seconds
def do_work(s):
  global start
  # Get the time and compute elapsed
  now = time.time()
  elapsed = now-start

  # Acquire lock
  stats_lock.acquire()
  # Update stats
  update_stats(elapsed)
  # Create the document
  create_document()
  # Release lock
  stats_lock.release()  
  
  # Write to file, TODO: Write to Tor-dir: data/status/
  write_file(file("./data/bw-informer/bw-document", "w"))
  # Some debugging
  plog("INFO", "Created new document for the last interval (" + str(elapsed) + ") seconds\n") # + bw_status)  
  # Reschedule
  start = time.time()
  s.enter(interval, 1, do_work, (s,))

# Run a scheduler that does work every interval
def start_sched(c):
  # Ge the network status
  nslist = c.get_network_status()
  read_routers(c, nslist)  
  # Setup scheduler
  s = sched.scheduler(time.time, time.sleep)
  start = time.time()
  total_start = time.time()
  s.enter(interval, 1, do_work, (s,))
  try:
    s.run()
  except KeyboardInterrupt:
    pass

# run()-method for one client-request
def client_thread(channel, details):
  channel.send(bw_status)
  channel.close()
  plog("INFO", "Sent status to: " + details[0] + ":" + str(details[1]))

# run()-method of the server-thread
def start_server():
  server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server.bind((listen_host, listen_port))
  server.listen(5)
  atexit.register(cleanup, *(server,))
  plog("INFO", "Listening on " + listen_host + ":" + str(listen_port))
  # Have the server serve "forever":
  while True:
    channel, details = server.accept()
    if not channel: break
    thr = threading.Thread(None, lambda: client_thread(channel, details))
    thr.setName("Client-Connection: " + details[0])
    thr.start()

# Close some given s (socket, connection, ...)
def cleanup(x):
  plog("INFO", "Closing socket/connection")
  x.close()

# Main function
def main(argv):
  plog("INFO", "bw-informer v" + VERSION)
  # Create connection to Tor
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((control_host, control_port))
  c = TorCtl.Connection(s)
  plog("INFO", "Successfully connected to running Tor process")
  # Set LinkHandler here
  c.set_event_handler(LinkHandler(c))
  # Close connection on exit
  atexit.register(cleanup, *(c,))
  # Start the connection thread
  c.launch_thread()
  c.authenticate()
  # Listen to some events
  c.set_events([TorCtl.EVENT_TYPE.ORCONN, 
                TorCtl.EVENT_TYPE.BW, 
                TorCtl.EVENT_TYPE.NS, 
                TorCtl.EVENT_TYPE.NEWDESC], True)
  # TODO: Set extra-info for descriptor here
  # Start server thread
  thr = threading.Thread(None, lambda: start_server())
  thr.setName("BW-Server")
  thr.setDaemon(1)
  thr.start()
  # Start the actual monitor here
  start_sched(c)

# Program entry point
if __name__ == '__main__':
  main(sys.argv)
