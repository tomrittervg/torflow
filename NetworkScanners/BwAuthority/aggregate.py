#!/usr/bin/python
import os
import re
import math
import sys
import socket
import time

sys.path.append("../../")
from TorCtl.TorUtil import plog
from TorCtl import TorCtl,TorUtil

bw_files = []
timestamps = {}
nodes = {}
prev_consensus = {}
ALPHA = 0.3333 # Prev consensus values count for 1/3 of the avg 

def base10_round(bw_val):
  # This keeps the first 3 decimal digits of the bw value only
  # to minimize changes for consensus diffs.
  # Resulting error is +/-0.5%
  return int(round(bw_val,-(int(math.log10(bw_val))-2)))

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
    self.chosen_sbw = None
    self.chosen_fbw = None
    self.sbw_ratio = None
    self.fbw_ratio = None
    self.ratio = None
    self.new_bw = None
    self.strm_bw = []
    self.filt_bw = []
    self.ns_bw = []

  def add_line(self, line):
    if self.idhex and self.idhex != line.idhex:
      raise Exception("Line mismatch")
    self.idhex = line.idhex
    self.nick = line.nick
    if line.slice_file not in self.node_data \
      or self.node_data[line.slice_file].timestamp < line.timestamp:
      self.node_data[line.slice_file] = NodeData(line.timestamp)

    nd = self.node_data[line.slice_file]
    nd.strm_bw.append(line.strm_bw)
    nd.filt_bw.append(line.filt_bw)
    nd.ns_bw.append(line.ns_bw)

    self.strm_bw = []
    self.filt_bw = []
    self.ns_bw = []

    for nd in self.node_data.itervalues():
      self.strm_bw.extend(nd.strm_bw)
      self.filt_bw.extend(nd.filt_bw)
      self.ns_bw.extend(nd.ns_bw)

  def avg_strm_bw(self):
    return sum(self.strm_bw)/float(len(self.strm_bw))

  def avg_filt_bw(self):
    return sum(self.filt_bw)/float(len(self.filt_bw))

  def avg_ns_bw(self):
    return sum(self.ns_bw)/float(len(self.ns_bw))

  def choose_strm_bw(self, net_avg):
    i = closest_to_one(map(lambda f: f/net_avg, self.strm_bw))
    self.chosen_sbw = i
    return self.chosen_sbw

  def choose_filt_bw(self, net_avg):
    i = closest_to_one(map(lambda f: f/net_avg, self.filt_bw))
    self.chosen_fbw = i
    return self.chosen_fbw

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
 
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((TorUtil.control_host,TorUtil.control_port))
  c = TorCtl.Connection(s)
  c.debug(file(argv[1]+"/aggregate-control.log", "w", buffering=0))
  c.authenticate_cookie(file(argv[1]+"/scanner.1/tor-data/control_auth_cookie",
                         "r"))

  ns_list = c.get_network_status()
  ns_list.sort(lambda x, y: x.bandwidth < y.bandwidth)
  got_ns_bw = False
  for n in ns_list:
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

  for da in argv[1:-1]:
    # First, create a list of the most recent files in the
    # scan dirs that are recent enough
    for root, dirs, f in os.walk(da):
      for ds in dirs:
        if re.match("^scanner.[\d+]$", ds):
          for sr, sd, files in os.walk(da+"/"+ds+"/scan-data"):
            for f in files:
              if re.search("^bws-[\S]+-done-", f):
                found_done = True
                fp = file(sr+"/"+f, "r")
                slicenum = sr+"/"+fp.readline()
                timestamp = float(fp.readline())
                fp.close()
                bw_files.append((slicenum, timestamp, sr+"/"+f))
                if slicenum not in timestamps or \
                     timestamps[slicenum] < timestamp:
                  timestamps[slicenum] = timestamp

  # FIXME: Hrmm.. there may be edge cases here where we have
  # an extra slice number that is never scanned again (ie the network
  # shrinks). This will leave us with really old timestamps.
  oldest_timestamp = min(timestamps.itervalues())

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
        print "Conversion error "+str(e)+" at "+l
    fp.close()
   
  pre_strm_avg = sum(map(lambda n: n.avg_strm_bw(), nodes.itervalues()))/ \
                  float(len(nodes))
  pre_filt_avg = sum(map(lambda n: n.avg_filt_bw(), nodes.itervalues()))/ \
                  float(len(nodes))

  for n in nodes.itervalues():
    n.choose_strm_bw(pre_strm_avg)
    n.choose_filt_bw(pre_filt_avg)

  true_strm_avg = sum(map(lambda n: n.strm_bw[n.chosen_sbw],
                       nodes.itervalues()))/float(len(nodes))
  true_filt_avg = sum(map(lambda n: n.filt_bw[n.chosen_fbw],
                       nodes.itervalues()))/float(len(nodes))

  for n in nodes.itervalues():
    n.fbw_ratio = n.filt_bw[n.chosen_fbw]/true_filt_avg
    n.sbw_ratio = n.strm_bw[n.chosen_sbw]/true_strm_avg
    if closest_to_one((n.sbw_ratio, n.fbw_ratio)) == 0:
      n.ratio = n.sbw_ratio
      n.new_bw = n.ns_bw[n.chosen_sbw]*n.ratio
    else:
      n.ratio = n.fbw_ratio
      n.new_bw = n.ns_bw[n.chosen_fbw]*n.ratio
    if n.idhex in prev_consensus and prev_consensus[n.idhex].bandwidth != None:
      prev_consensus[n.idhex].measured = True
      n.new_bw = ((prev_consensus[n.idhex].bandwidth*ALPHA + n.new_bw)/(ALPHA + 1))/1024.0

  for n in prev_consensus.itervalues():
    if not n.measured:
      if "Fast" in n.flags and "Running" in n.flags:
        r = c.get_router(n)
        if r and not r.down and r.bw > 0:
          if time.mktime(r.published.utctimetuple()) - r.uptime \
                 < oldest_timestamp:
            # We still tend to miss about 80 nodes even with these
            # checks.. Possibly going in and out of hibernation?
            plog("INFO", "Didn't measure "+n.idhex+"="+n.nickname)

  n_print = nodes.values()
  n_print.sort(lambda x,y: int(x.new_bw) - int(y.new_bw))

  out = file(argv[-1], "w")
  out.write(str(int(round(oldest_timestamp,0)))+"\n")
  for n in n_print:
    out.write("node_id="+n.idhex+" bw="+str(base10_round(n.new_bw))+" nick="+n.nick+"\n")
  out.close()
 
if __name__ == "__main__":
  main(sys.argv)
