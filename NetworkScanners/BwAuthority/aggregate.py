#!/usr/bin/python
import os
import re
import math
import sys


bw_files = {}
nodes = {}

def base10_round(bw_val):
  # This keeps the first 3 decimal digits of the bw value only
  # to minimize changes for consensus diffs.
  # Resulting error is +/-0.05%
  return round(bw_val,-(int(math.log10(bw_val))-2))

def closest_to_one(ratio_list):
  min_dist = 0x7fffffff
  min_item = -1
  for i in xrange(len(ratio_list)):
    if abs(1.0-ratio_list[i]) < min_dist:
      min_dist = abs(1.0-ratio_list[i])
      min_item = i
  return min_item

class Node:
  def __init__(self):
    self.idhex = None
    self.strm_bw = []
    self.filt_bw = []
    self.ns_bw = []
    self.chosen_sbw = None
    self.chosen_fbw = None
    self.sbw_ratio = None
    self.fbw_ratio = None
    self.ratio = None
    self.new_bw = None

  def add_line(self, line):
    if self.idhex != line.idhex:
      raise Exception("Line mismatch")
    self.strm_bw.append(line.strm_bw)     
    self.filt_bw.append(line.filt_bw)     
    self.ns_bw.append(line.ns_bw)     

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
  def __init__(self, line):
    self.idhex = re.search("[\s]*node_id=([\S]+)[\s]*", line).group(0)
    self.strm_bw = int(re.search("[\s]*strm_bw=([\d]+)[\s]*", line).group(0))
    self.filt_bw = int(re.search("[\s]*filt_bw=([\d]+)[\s]*", line).group(0))
    self.ns_bw = int(re.search("[\s]*ns_bw=([\d]+)[\s]*", line).group(0))

def main(argv):
  for d in argv[1:-1]:
    # First, create a list of the most recent files in the
    # scan dirs that are recent enough
    for root, dirs, files in os.walk(d):
      for f in files:
        if f.find("-done-"):
          fp = file(f, "r")
          ranks = fp.readline()
          timestamp = float(fp.readline())
          fp.close()
          if ranks not in bw_files or bw_files[ranks][0] < timestamp:
            bw_files[ranks] = (timestamp, f)
  
  for (t,f) in bw_files.itervalues():
    fp = file(f, "r")
    fp.readline()
    fp.readline()
    for l in fp.readlines():
      line = Line(l)
      if line.idhex not in nodes:
        n = Node()
        nodes[line.idhex] = n
      else:
        n = nodes[line.idhex]
      n.add_line(line)        
    fp.close()
   
  pre_strm_avg = sum(map(lambda n: n.avg_strm_bw(), nodes.itervalues()))/ \
                  float(len(nodes))
  pre_filt_avg = sum(map(lambda n: n.avg_filt_bw(), nodes.itervalues()))/ \
                  float(len(nodes))

  for n in nodes.itervalues():
    n.choose_strm_bw(pre_strm_avg) 
    n.choose_filt_bw(pre_filt_avg)

  true_strm_avg = sum(map(lambda n: n.chosen_sbw, nodes.itervalues()))/ \
                  float(len(nodes))
  true_filt_avg = sum(map(lambda n: n.chosen_fbw, nodes.itervalues()))/ \
                  float(len(nodes))

  for n in nodes.itervalues():
    n.fbw_ratio = n.filt_bw[n.chosen_fbw]/true_filt_avg
    n.sbw_ratio = n.strm_bw[n.chosen_sbw]/true_strm_avg
    if closest_to_one((n.sbw_ratio, n.fbw_ratio)) == 0:
      n.ratio = n.sbw_ratio
      n.new_bw = n.ns_bw[n.chosen_sbw]*n.ratio
    else: 
      n.ratio = n.fbw_ratio
      n.new_bw = n.ns_bw[n.chosen_fbw]*n.ratio

  n_print = nodes.values()
  n_print.sort(lambda x,y: x.new_bw < y.new_bw)

  oldest_timestamp = min(map(lambda (t,f): t, bw_files.itervalues()))
  out = file(argv[-1], "w")
  out.write(str(int(round(oldest_timestamp,0)))+"\n")
  for n in n_print:
    out.write("node_id="+n.idhex+" bw="+str(base10_round(n.new_bw))+"\n")
  out.close()
 
if __name__ == "__main__":
  main(sys.argv)
