#!/usr/bin/python
import os
import re
import math
import sys
import socket
import time
import traceback

sys.path.append("../../")
from TorCtl.TorUtil import plog
from TorCtl import TorCtl,TorUtil

bw_files = []
timestamps = {}
nodes = {}
prev_consensus = {}
ALPHA = 0.3333 # Prev consensus values count for 1/3 of the avg 
MIN_REPORT = 60 # Percent of the network we must measure before reporting
# Keep most measurements in consideration. The code below chooses
# the most recent one. 15 days is just to stop us from choking up 
# all the CPU once these things run for a year or so.
MAX_AGE = 60*60*24*15 

def base10_round(bw_val):
  # This keeps the first 3 decimal digits of the bw value only
  # to minimize changes for consensus diffs.
  # Resulting error is +/-0.5%
  if bw_val == 0:
    plog("NOTICE", "Zero bandwidth!")
    return 0
  return int(max((1000,
                   round(round(bw_val,-(int(math.log10(bw_val))-2)),
                                                       -3)))/1000)

def closest_to_one(ratio_list):
  min_dist = 0x7fffffff
  min_item = -1
  for i in xrange(len(ratio_list)):
    if abs(1.0-ratio_list[i]) < min_dist:
      min_dist = abs(1.0-ratio_list[i])
      min_item = i
  return min_item

class NodeData:
  def __init__(self, timestamp):
    self.strm_bw = []
    self.filt_bw = []
    self.ns_bw = []
    self.timestamp = timestamp

class Node:
  def __init__(self):
    self.node_data = {}
    self.idhex = None
    self.nick = None
    self.chosen_time = None
    self.chosen_sbw = None
    self.chosen_fbw = None
    self.sbw_ratio = None
    self.fbw_ratio = None
    self.ratio = None
    self.new_bw = None
    self.change = None
    self.strm_bw = []
    self.filt_bw = []
    self.ns_bw = []
    self.timestamps = []

  def add_line(self, line):
    if self.idhex and self.idhex != line.idhex:
      raise Exception("Line mismatch")
    self.idhex = line.idhex
    self.nick = line.nick
    if line.slice_file not in self.node_data \
      or self.node_data[line.slice_file].timestamp < line.timestamp:
      self.node_data[line.slice_file] = NodeData(line.timestamp)

    # FIXME: This is kinda nutty. Can we simplify? For instance,
    # do these really need to be lists inside the nd?
    nd = self.node_data[line.slice_file]
    nd.strm_bw.append(line.strm_bw)
    nd.filt_bw.append(line.filt_bw)
    nd.ns_bw.append(line.ns_bw)

    self.strm_bw = []
    self.filt_bw = []
    self.ns_bw = []
    self.timestamps = []

    for nd in self.node_data.itervalues():
      self.strm_bw.extend(nd.strm_bw)
      self.filt_bw.extend(nd.filt_bw)
      self.ns_bw.extend(nd.ns_bw)
      for i in xrange(len(nd.ns_bw)):
        self.timestamps.append(nd.timestamp)

  def avg_strm_bw(self):
    return sum(self.strm_bw)/float(len(self.strm_bw))

  def avg_filt_bw(self):
    return sum(self.filt_bw)/float(len(self.filt_bw))

  def avg_ns_bw(self):
    return sum(self.ns_bw)/float(len(self.ns_bw))

  # This can be bad for bootstrapping or highly bw-variant nodes... 
  # we will choose an old measurement in that case.. We need
  # to build some kind of time-bias here..
  def _choose_strm_bw_one(self, net_avg):
    i = closest_to_one(map(lambda f: f/net_avg, self.strm_bw))
    self.chosen_sbw = i
    return self.chosen_sbw

  def _choose_filt_bw_one(self, net_avg):
    i = closest_to_one(map(lambda f: f/net_avg, self.filt_bw))
    self.chosen_fbw = i
    return self.chosen_fbw

  # Simply return the most recent one instead of this
  # closest-to-one stuff
  def choose_filt_bw(self, new_avg):
    max_idx = 0
    for i in xrange(len(self.timestamps)):
      if self.timestamps[i] > self.timestamps[max_idx]:
        max_idx = i
    self.chosen_fbw = max_idx
    return self.chosen_fbw

  def choose_strm_bw(self, new_avg):
    max_idx = 0
    for i in xrange(len(self.timestamps)):
      if self.timestamps[i] > self.timestamps[max_idx]:
        max_idx = i
    self.chosen_sbw = max_idx
    return self.chosen_sbw

class Line:
  def __init__(self, line, slice_file, timestamp):
    self.idhex = re.search("[\s]*node_id=([\S]+)[\s]*", line).group(1)
    self.nick = re.search("[\s]*nick=([\S]+)[\s]*", line).group(1)
    self.strm_bw = int(re.search("[\s]*strm_bw=([\S]+)[\s]*", line).group(1))
    self.filt_bw = int(re.search("[\s]*filt_bw=([\S]+)[\s]*", line).group(1))
    self.ns_bw = int(re.search("[\s]*ns_bw=([\S]+)[\s]*", line).group(1))
    self.slice_file = slice_file
    self.timestamp = timestamp

def main(argv):
  TorUtil.read_config(argv[1]+"/scanner.1/bwauthority.cfg")
  TorUtil.loglevel = "NOTICE"
 
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((TorUtil.control_host,TorUtil.control_port))
  c = TorCtl.Connection(s)
  c.debug(file(argv[1]+"/aggregate-control.log", "w", buffering=0))
  c.authenticate_cookie(file(argv[1]+"/scanner.1/tor-data/control_auth_cookie",
                         "r"))

  ns_list = c.get_network_status()
  for n in ns_list:
    if n.bandwidth == None: n.bandwidth = -1
  ns_list.sort(lambda x, y: y.bandwidth - x.bandwidth)
  for n in ns_list:
    if n.bandwidth == -1: n.bandwidth = None
  got_ns_bw = False
  max_rank = len(ns_list)

  # FIXME: This is poor form.. We should subclass the Networkstatus class
  # instead of just adding members
  for i in xrange(max_rank):
    n = ns_list[i]
    n.list_rank = i
    if n.bandwidth == None:
      plog("NOTICE", "Your Tor is not providing NS w bandwidths for "+n.idhex)
    else:
      got_ns_bw = True
    n.measured = False
    prev_consensus["$"+n.idhex] = n

  if not got_ns_bw:
    # Sometimes the consensus lacks a descriptor. In that case,
    # it will skip outputting 
    plog("ERROR", "Your Tor is not providing NS w bandwidths!")
    sys.exit(0)

  # Take the most recent timestamp from each scanner 
  # and use the oldest for the timestamp of the result.
  # That way we can ensure all the scanners continue running.
  scanner_timestamps = []
  for da in argv[1:-1]:
    # First, create a list of the most recent files in the
    # scan dirs that are recent enough
    for root, dirs, f in os.walk(da):
      for ds in dirs:
        if re.match("^scanner.[\d+]$", ds):
          newest_timestamp = 0
          for sr, sd, files in os.walk(da+"/"+ds+"/scan-data"):
            for f in files:
              if re.search("^bws-[\S]+-done-", f):
                found_done = True
                fp = file(sr+"/"+f, "r")
                slicenum = sr+"/"+fp.readline()
                timestamp = float(fp.readline())
                fp.close()
                # old measurements are probably
                # better than no measurements. We may not
                # measure hibernating routers for days.
                # This filter is just to remove REALLY old files
                if time.time() - timestamp > MAX_AGE:
                  plog("INFO", "Skipping old file "+f)
                  continue
                if timestamp > newest_timestamp:
                  newest_timestamp = timestamp
                bw_files.append((slicenum, timestamp, sr+"/"+f))
                # FIXME: Can we kill this?
                if slicenum not in timestamps or \
                     timestamps[slicenum] < timestamp:
                  timestamps[slicenum] = timestamp
          scanner_timestamps.append(newest_timestamp)

  # Need to only use most recent slice-file for each node..
  for (s,t,f) in bw_files:
    fp = file(f, "r")
    fp.readline() # slicenum
    fp.readline() # timestamp
    for l in fp.readlines():
      try:
        line = Line(l,s,t)
        if line.idhex not in nodes:
          n = Node()
          nodes[line.idhex] = n
        else:
          n = nodes[line.idhex]
        n.add_line(line)
      except ValueError,e:
        plog("NOTICE", "Conversion error "+str(e)+" at "+l)
    fp.close()

  if len(nodes) == 0:
    plog("NOTICE", "No scan results yet.")
    sys.exit(1)
 
  pre_strm_avg = sum(map(lambda n: n.avg_strm_bw(), nodes.itervalues()))/ \
                  float(len(nodes))
  pre_filt_avg = sum(map(lambda n: n.avg_filt_bw(), nodes.itervalues()))/ \
                  float(len(nodes))

  plog("INFO", "Network pre_strm_avg: "+str(pre_strm_avg))
  plog("INFO", "Network pre_filt_avg: "+str(pre_filt_avg))

  for n in nodes.itervalues():
    n.choose_strm_bw(pre_strm_avg)
    n.choose_filt_bw(pre_filt_avg)
    plog("DEBUG", "Node "+n.nick+" chose sbw: "+\
                str(n.strm_bw[n.chosen_sbw])+" fbw: "+\
                str(n.filt_bw[n.chosen_fbw]))

  true_strm_avg = sum(map(lambda n: n.strm_bw[n.chosen_sbw],
                       nodes.itervalues()))/float(len(nodes))
  true_filt_avg = sum(map(lambda n: n.filt_bw[n.chosen_fbw],
                       nodes.itervalues()))/float(len(nodes))

  plog("INFO", "Network true_strm_avg: "+str(true_strm_avg))
  plog("INFO", "Network true_filt_avg: "+str(true_filt_avg))

  for n in nodes.itervalues():
    n.fbw_ratio = n.filt_bw[n.chosen_fbw]/true_filt_avg
    n.sbw_ratio = n.strm_bw[n.chosen_sbw]/true_strm_avg
    if n.sbw_ratio > n.fbw_ratio:
      n.ratio = n.sbw_ratio
      n.new_bw = n.ns_bw[n.chosen_sbw]*n.ratio
      n.chosen_time = n.timestamps[n.chosen_sbw]
      n.change = 0 - n.ns_bw[n.chosen_sbw]
    else:
      n.ratio = n.fbw_ratio
      n.new_bw = n.ns_bw[n.chosen_fbw]*n.ratio
      n.chosen_time = n.timestamps[n.chosen_fbw]
      n.change = 0 - n.ns_bw[n.chosen_fbw]
    if n.idhex in prev_consensus and prev_consensus[n.idhex].bandwidth != None:
      prev_consensus[n.idhex].measured = True
      # XXX: Maybe we should base this on the consensus value
      # at the time of measurement from the Node class.
      n.new_bw = ((prev_consensus[n.idhex].bandwidth*ALPHA + n.new_bw)/(ALPHA + 1))
    n.change += n.new_bw

  oldest_timestamp = min(map(lambda n: n.chosen_time,
             filter(lambda n: n.idhex in prev_consensus,
                       nodes.itervalues())))
  plog("INFO", "Oldest measured node: "+time.ctime(oldest_timestamp))

  missed_nodes = 0.0
  for n in prev_consensus.itervalues():
    if not n.measured:
      if "Fast" in n.flags and "Running" in n.flags:
        try:
          r = c.get_router(n)
        except TorCtl.ErrorReply:
          r = None
        if r and not r.down and r.bw > 0:
          #if time.mktime(r.published.utctimetuple()) - r.uptime \
          #       < oldest_timestamp:
          missed_nodes += 1.0
          # We still tend to miss about 80 nodes even with these
          # checks.. Possibly going in and out of hibernation?
          plog("INFO", "Didn't measure "+n.idhex+"="+n.nickname+" at "+str(round((100.0*n.list_rank)/max_rank,1))+" "+str(n.bandwidth))

  measured_pct = round(100.0*len(nodes)/(len(nodes)+missed_nodes),1)
  if measured_pct < MIN_REPORT:
    plog("NOTICE", "Did not measure "+str(MIN_REPORT)+"% of nodes yet ("+str(measured_pct)+"%)")
    sys.exit(1)

  plog("NOTICE", "Measured "+str(measured_pct)+"% of all tor nodes.")

  n_print = nodes.values()
  n_print.sort(lambda x,y: int(y.change) - int(x.change))

  out = file(argv[-1], "w")
  out.write(str(int(round(min(scanner_timestamps),0)))+"\n")
  for n in n_print:
    out.write("node_id="+n.idhex+" bw="+str(base10_round(n.new_bw))+" diff="+str(int(round(n.change/1000.0,0)))+ " nick="+n.nick+ " measured_at="+str(int(n.chosen_time))+"\n")
  out.close()
 
if __name__ == "__main__":
  try:
    main(sys.argv)
  except socket.error, e:
    traceback.print_exc()
    plog("WARN", "Socket error. Are the scanning Tors running?")
    sys.exit(1)
  except Exception, e:
    plog("ERROR", "Exception during aggregate: "+str(e))
    traceback.print_exc()
    sys.exit(1)
  sys.exit(0)
