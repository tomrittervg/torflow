#!/usr/bin/env python
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
nodes = {}
prev_consensus = {}

# Hack to kill voting on guards while the network rebalances
IGNORE_GUARDS = 0

# The guard measurement period is based on the client turnover
# rate for guard nodes
GUARD_SAMPLE_RATE = 2*7*24*60*60 # 2wks

# PID constant defaults. May be overridden by consensus
# https://en.wikipedia.org/wiki/PID_controller#Ideal_versus_standard_PID_form
K_p = 1.0

# We expect to correct steady state error in 5 samples (guess)
T_i = 0

# T_i_decay is a weight factor to govern how fast integral sums
# decay. For the values of T_i that we care about, T_i_decay represents
# the fraction of integral sum that is eliminated after T_i sample rounds.
# This decay is non-standard, but we do it to avoid overflow
T_i_decay = 0

# We can only expect to predict less than one sample into the future, as
# after 1 sample, clients will have migrated
# FIXME: Our prediction ability is a function of the consensus uptake time
# vs measurement rate
T_d = 0

NODE_CAP = 0.05

MIN_REPORT = 60 # Percent of the network we must measure before reporting

# Keep most measurements in consideration. The code below chooses
# the most recent one. 28 days is just to stop us from choking up 
# all the CPU once these things run for a year or so.
# Note that the Guard measurement interval of 2 weeks means that this
# value can't get much below that.
MAX_AGE = 2*GUARD_SAMPLE_RATE

# If the resultant scan file is older than 1.5 days, something is wrong
MAX_SCAN_AGE = 60*60*24*1.5

# path to git repos (.git)
PATH_TO_TORFLOW_REPO = '../../.git/'
PATH_TO_TORCTL_REPO = '../../.git/modules/TorCtl/'

def base10_round(bw_val):
  # This keeps the first 3 decimal digits of the bw value only
  # to minimize changes for consensus diffs.
  # Resulting error is +/-0.5%
  if bw_val == 0:
    plog("INFO", "Zero input bandwidth.. Upping to 1")
    return 1
  else:
    ret = int(max((1000,
                   round(round(bw_val,-(int(math.log10(bw_val))-2)),
                                                       -3)))/1000)
    if ret == 0:
      plog("INFO", "Zero output bandwidth.. Upping to 1")
      return 1
    return ret

class Node:
  def __init__(self):
    self.ignore = False
    self.idhex = None
    self.nick = None
    self.sbw_ratio = None
    self.fbw_ratio = None
    self.pid_bw = 0
    self.pid_error = 0
    self.prev_error = 0
    self.pid_error_sum = 0
    self.pid_delta = 0
    self.ratio = None
    self.new_bw = None
    self.change = None
    self.use_bw = -1
    self.flags = ""

    # measurement vars from bwauth lines
    self.measured_at = 0
    self.strm_bw = 0
    self.filt_bw = 0
    self.ns_bw = 0
    self.desc_bw = 0
    self.circ_fail_rate = 0
    self.strm_fail_rate = 0
    self.updated_at = 0

  def revert_to_vote(self, vote):
    self.copy_vote(vote)
    self.pid_error = vote.pid_error # Set
    self.measured_at = vote.measured_at # Set

  def copy_vote(self, vote):
    self.new_bw = vote.bw*1000 # Not set yet
    self.pid_bw = vote.pid_bw  # Not set yet
    self.pid_error_sum = vote.pid_error_sum # Not set yet
    self.pid_delta = vote.pid_delta # Not set yet

  def get_pid_bw(self, prev_vote, kp, ki, kd, kidecay, update=True):
    if not update:
      return self.use_bw \
                  + kp*self.use_bw*self.pid_error \
                  + ki*self.use_bw*self.pid_error_sum \
                  + kd*self.use_bw*self.pid_delta

    self.prev_error = prev_vote.pid_error

    self.pid_bw = self.use_bw \
                             + kp*self.use_bw*self.pid_error \
                             + ki*self.use_bw*self.integral_error() \
                             + kd*self.use_bw*self.d_error_dt()

    # We decay the interval each round to keep it bounded.
    # This decay is non-standard. We do it to avoid overflow
    self.pid_error_sum = prev_vote.pid_error_sum*kidecay + self.pid_error

    return self.pid_bw

  def node_class(self):
    if "Guard" in self.flags and "Exit" in self.flags:
      return "Guard+Exit"
    elif "Guard" in self.flags:
      return "Guard"
    elif "Exit" in self.flags:
      return "Exit"
    else:
      return "Middle"

  # Time-weighted sum of error per unit of time (measurement sample)
  def integral_error(self):
    if self.prev_error == 0:
      return 0
    return self.pid_error_sum

  # Rate of change in error from the last measurement sample
  def d_error_dt(self):
    if self.prev_error == 0:
      self.pid_delta = 0
    else:
      self.pid_delta = self.pid_error - self.prev_error
    return self.pid_delta

  def add_line(self, line):
    if self.idhex and self.idhex != line.idhex:
      raise Exception("Line mismatch")
    self.idhex = line.idhex
    self.nick = line.nick
    if line.measured_at > self.measured_at:
      self.measured_at = self.updated_at = line.measured_at
      self.strm_bw = line.strm_bw
      self.filt_bw = line.filt_bw
      self.ns_bw = line.ns_bw
      self.desc_bw = line.desc_bw
      self.circ_fail_rate = line.circ_fail_rate
      self.strm_fail_rate = line.strm_fail_rate
      self.scanner = line.filename

class Line:
  def __init__(self, line, slice_file, timestamp, filename):
    self.idhex = re.search("[\s]*node_id=([\S]+)[\s]*", line).group(1)
    self.nick = re.search("[\s]*nick=([\S]+)[\s]*", line).group(1)
    self.strm_bw = int(re.search("[\s]*strm_bw=([\S]+)[\s]*", line).group(1))
    self.filt_bw = int(re.search("[\s]*filt_bw=([\S]+)[\s]*", line).group(1))
    self.ns_bw = int(re.search("[\s]*ns_bw=([\S]+)[\s]*", line).group(1))
    self.desc_bw = int(re.search("[\s]*desc_bw=([\S]+)[\s]*", line).group(1))
    self.slice_file = slice_file
    self.filename = filename
    self.measured_at = timestamp
    try:
      self.circ_fail_rate = float(re.search("[\s]*circ_fail_rate=([\S]+)[\s]*", line).group(1))
    except:
      self.circ_fail_rate = 0
    try:
      self.strm_fail_rate = float(re.search("[\s]*strm_fail_rate=([\S]+)[\s]*", line).group(1))
    except:
      self.strm_fail_rate = 0


class Vote:
  def __init__(self, line):
    # node_id=$DB8C6D8E0D51A42BDDA81A9B8A735B41B2CF95D1 bw=231000 diff=209281 nick=rainbowwarrior measured_at=1319822504
    self.idhex = re.search("[\s]*node_id=([\S]+)[\s]*", line).group(1)
    self.nick = re.search("[\s]*nick=([\S]+)[\s]*", line).group(1)
    self.bw = int(re.search("[\s]+bw=([\S]+)[\s]*", line).group(1))
    self.measured_at = int(re.search("[\s]*measured_at=([\S]+)[\s]*", line).group(1))
    try:
      self.pid_error = float(re.search("[\s]*pid_error=([\S]+)[\s]*", line).group(1))
      self.pid_error_sum = float(re.search("[\s]*pid_error_sum=([\S]+)[\s]*", line).group(1))
      self.pid_delta = float(re.search("[\s]*pid_delta=([\S]+)[\s]*", line).group(1))
      self.pid_bw = float(re.search("[\s]*pid_bw=([\S]+)[\s]*", line).group(1))
    except:
      plog("NOTICE", "No previous PID data.")
      self.pid_bw = self.bw
      self.pid_error = 0
      self.pid_delta = 0
      self.pid_error_sum = 0
    try:
      self.updated_at = int(re.search("[\s]*updated_at=([\S]+)[\s]*", line).group(1))
    except:
      plog("INFO", "No updated_at field for "+self.nick+"="+self.idhex)
      self.updated_at = self.measured_at


class VoteSet:
  def __init__(self, filename):
    self.vote_map = {}
    try:
      f = file(filename, "r")
      f.readline()
      for line in f.readlines():
        vote = Vote(line)
        self.vote_map[vote.idhex] = vote
    except IOError:
      plog("NOTICE", "No previous vote data.")

# Misc items we need to get out of the consensus
class ConsensusJunk:
  def __init__(self, c):
    cs_bytes = c.sendAndRecv("GETINFO dir/status-vote/current/consensus\r\n")[0][2]
    self.bwauth_pid_control = True
    self.group_by_class = False
    self.use_pid_tgt = False
    self.use_circ_fails = False
    self.use_best_ratio = True
    self.use_desc_bw = True
    self.use_mercy = False

    self.guard_sample_rate = GUARD_SAMPLE_RATE
    self.pid_max = 500.0
    self.K_p = K_p
    self.T_i = T_i
    self.T_d = T_d
    self.T_i_decay = T_i_decay

    try:
      cs_params = re.search("^params ((?:[\S]+=[\d]+[\s]?)+)",
                                     cs_bytes, re.M).group(1).split()
      for p in cs_params:
        if p == "bwauthpid=0":
          self.bwauth_pid_control = False
        elif p == "bwauthnsbw=1":
          self.use_desc_bw = False
          plog("INFO", "Using NS bandwidth directly for feedback")
        elif p == "bwauthcircs=1":
          self.use_circ_fails = True
          plog("INFO", "Counting circuit failures")
        elif p == "bwauthbestratio=0":
          self.use_best_ratio = False
          plog("INFO", "Choosing larger of sbw vs fbw")
        elif p == "bwauthbyclass=1":
          self.group_by_class = True
          plog("INFO", "Grouping nodes by flag-class")
        elif p == "bwauthpidtgt=1":
          self.use_pid_tgt = True
          plog("INFO", "Using filtered PID target")
        elif p == "bwauthmercy=1":
          self.use_mercy = True
          plog("INFO", "Showing mercy on gimpy nodes")
        elif p.startswith("bwauthkp="):
          self.K_p = int(p.split("=")[1])/10000.0
          plog("INFO", "Got K_p=%f from consensus." % self.K_p)
        elif p.startswith("bwauthti="):
          self.T_i = (int(p.split("=")[1])/10000.0)
          plog("INFO", "Got T_i=%f from consensus." % self.T_i)
        elif p.startswith("bwauthtd="):
          self.T_d = (int(p.split("=")[1])/10000.0)
          plog("INFO", "Got T_d=%f from consensus." % self.T_d)
        elif p.startswith("bwauthtidecay="):
          self.T_i_decay = (int(p.split("=")[1])/10000.0)
          plog("INFO", "Got T_i_decay=%f from consensus." % self.T_i_decay)
        elif p.startswith("bwauthpidmax="):
          self.pid_max = (int(p.split("=")[1])/10000.0)
          plog("INFO", "Got pid_max=%f from consensus." % self.pid_max)
        elif p.startswith("bwauthguardrate="):
          self.guard_sample_rate = int(p.split("=")[1])
          plog("INFO", "Got guard_sample_rate=%d from consensus." %
                       self.guard_sample_rate)
    except:
      plog("NOTICE", "Bw auth PID control disabled due to parse error.")
      traceback.print_exc()

    if self.T_i == 0:
      self.K_i = 0
      self.K_i_decay = 0
    else:
      self.K_i = self.K_p/self.T_i
      self.K_i_decay = (1.0-self.T_i_decay/self.T_i)

    self.K_d = self.K_p*self.T_d

    plog("INFO", "Got K_p=%f K_i=%f K_d=%f K_i_decay=%f" %
                  (self.K_p, self.K_i, self.K_d, self.K_i_decay))

    self.bw_weights = {}
    try:
      bw_weights = re.search("^bandwidth-weights ((?:[\S]+=[\d]+[\s]?)+)",
                           cs_bytes, re.M).group(1).split()
      for b in bw_weights:
        pair = b.split("=")
        self.bw_weights[pair[0]] = int(pair[1])/10000.0
    except:
      plog("WARN", "No bandwidth weights in consensus!")
      self.bw_weights["Wgd"] = 0
      self.bw_weights["Wgg"] = 1.0

def write_file_list(datadir):
  files = {64*1024:"64M", 32*1024:"32M", 16*1024:"16M", 8*1024:"8M",
                4*1024:"4M", 2*1024:"2M", 1024:"1M", 512:"512k",
                256:"256k", 128:"128k", 64:"64k", 32:"32k", 16:"16k", 0:"16k"}
  file_sizes = files.keys()
  node_fbws = map(lambda x: 5*x.filt_bw, nodes.itervalues())
  file_pairs = []
  file_sizes.sort(reverse=True)
  node_fbws.sort()
  prev_size = file_sizes[-1]
  prev_pct = 0
  i = 0

  # The idea here is to grab the largest file size such
  # that 5*bw < file, and do this for each file size.
  for bw in node_fbws:
    i += 1
    pct = 100-(100*i)/len(node_fbws)
    # If two different file sizes serve one percentile, go with the
    # smaller file size (ie skip this one)
    if pct == prev_pct:
      continue
    for f in xrange(len(file_sizes)):
      if bw > file_sizes[f]*1024 and file_sizes[f] > prev_size:
        next_f = max(f-1,0)
        file_pairs.append((pct,files[file_sizes[next_f]]))
        prev_size = file_sizes[f]
        prev_pct = pct
        break

  file_pairs.reverse()

  outfile = file(datadir+"/bwfiles.new", "w")
  for f in file_pairs:
   outfile.write(str(f[0])+" "+f[1]+"\n")
  outfile.write(".\n")
  outfile.close()
  # atomic on POSIX
  os.rename(datadir+"/bwfiles.new", datadir+"/bwfiles")

def main(argv):
  TorUtil.read_config(argv[1]+"/scanner.1/bwauthority.cfg")
  TorUtil.logfile = "data/aggregate-debug.log"

  (branch, head) = TorUtil.get_git_version(PATH_TO_TORFLOW_REPO)
  plog('NOTICE', 'TorFlow Version: %s' % branch+' '+head)
  (branch, head) = TorUtil.get_git_version(PATH_TO_TORCTL_REPO)
  plog('NOTICE', 'TorCtl Version: %s' % branch+' '+head)

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((TorUtil.control_host,TorUtil.control_port))
  c = TorCtl.Connection(s)
  c.debug(file(argv[1]+"/aggregate-control.log", "w", buffering=0))
  c.authenticate_cookie(file(argv[1]+"/tor.1/control_auth_cookie",
                         "r"))

  ns_list = c.get_network_status()
  for n in ns_list:
    if n.bandwidth == None: n.bandwidth = -1
  ns_list.sort(lambda x, y: int(y.bandwidth/10000.0 - x.bandwidth/10000.0))
  for n in ns_list:
    if n.bandwidth == -1: n.bandwidth = None
  got_ns_bw = False
  max_rank = len(ns_list)

  cs_junk = ConsensusJunk(c)

  # TODO: This is poor form.. We should subclass the Networkstatus class
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
  scanner_timestamps = {}
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
                fp = file(sr+"/"+f, "r")
                slicenum = sr+"/"+fp.readline()
                timestamp = float(fp.readline())
                fp.close()
                # old measurements are probably
                # better than no measurements. We may not
                # measure hibernating routers for days.
                # This filter is just to remove REALLY old files
                if time.time() - timestamp > MAX_AGE:
                  sqlf = f.replace("bws-", "sql-")
                  plog("INFO", "Removing old file "+f+" and "+sqlf)
                  os.remove(sr+"/"+f)
                  try:
                    os.remove(sr+"/"+sqlf)
                  except:
                    pass # In some cases the sql file may not exist
                  continue
                if timestamp > newest_timestamp:
                  newest_timestamp = timestamp
                bw_files.append((slicenum, timestamp, sr+"/"+f))
          scanner_timestamps[ds] = newest_timestamp

  # Need to only use most recent slice-file for each node..
  for (s,t,f) in bw_files:
    fp = file(f, "r")
    fp.readline() # slicenum
    fp.readline() # timestamp
    for l in fp.readlines():
      try:
        line = Line(l,s,t,f.replace(argv[1], ""))
        if line.idhex not in nodes:
          n = Node()
          nodes[line.idhex] = n
        else:
          n = nodes[line.idhex]
        n.add_line(line)
      except ValueError,e:
        plog("NOTICE", "Conversion error "+str(e)+" at "+l)
      except AttributeError, e:
        plog("NOTICE", "Slice file format error "+str(e)+" at "+l)
      except Exception, e:
        plog("WARN", "Unknown slice parse error "+str(e)+" at "+l)
        traceback.print_exc()
    fp.close()

  if len(nodes) == 0:
    plog("NOTICE", "No scan results yet.")
    sys.exit(1)

  for idhex in nodes.iterkeys():
    if idhex in prev_consensus:
      nodes[idhex].flags = prev_consensus[idhex].flags

  true_filt_avg = {}
  pid_tgt_avg = {}
  true_strm_avg = {}
  true_circ_avg = {}

  if cs_junk.bwauth_pid_control:
    # Penalize nodes for circuit failure: it indicates CPU pressure
    # TODO: Potentially penalize for stream failure, if we run into
    # socket exhaustion issues..
    plog("INFO", "PID control enabled")

    # TODO: Please forgive me for this, I wanted to see
    # these loglines, so we go aead and run this code regardless of
    # the group_by_class setting, and just reset the values if it is not set.

    for cl in ["Guard+Exit", "Guard", "Exit", "Middle"]:
      c_nodes = filter(lambda n: n.node_class() == cl, nodes.itervalues())
      if len(c_nodes) > 0:
        true_filt_avg[cl] = sum(map(lambda n: n.filt_bw, c_nodes))/float(len(c_nodes))
        true_strm_avg[cl] = sum(map(lambda n: n.strm_bw, c_nodes))/float(len(c_nodes))
        true_circ_avg[cl] = sum(map(lambda n: (1.0-n.circ_fail_rate),
                             c_nodes))/float(len(c_nodes))
      else:
        true_filt_avg[cl] = 0.0
        true_strm_avg[cl] = 0.0
        true_circ_avg[cl] = 0.0

      # FIXME: This may be expensive
      pid_tgt_avg[cl] = true_filt_avg[cl]
      prev_pid_avg = 2*pid_tgt_avg[cl]

      while prev_pid_avg > pid_tgt_avg[cl]:
        f_nodes = filter(lambda n: n.desc_bw >= pid_tgt_avg[cl], c_nodes)
        prev_pid_avg = pid_tgt_avg[cl]
        if len(f_nodes) > 0:
          pid_tgt_avg[cl] = sum(map(lambda n: n.filt_bw, f_nodes))/float(len(f_nodes))
        else:
          pid_tgt_avg[cl] = 0.0

      plog("INFO", "Network true_filt_avg["+cl+"]: "+str(true_filt_avg[cl]))
      plog("INFO", "Network pid_tgt_avg["+cl+"]: "+str(pid_tgt_avg[cl]))
      plog("INFO", "Network true_circ_avg["+cl+"]: "+str(true_circ_avg[cl]))

    filt_avg = sum(map(lambda n: n.filt_bw, nodes.itervalues()))/float(len(nodes))
    strm_avg = sum(map(lambda n: n.strm_bw, nodes.itervalues()))/float(len(nodes))
    circ_avg = sum(map(lambda n: (1.0-n.circ_fail_rate),
                       nodes.itervalues()))/float(len(nodes))
    plog("INFO", "Network filt_avg: "+str(filt_avg))
    plog("INFO", "Network circ_avg: "+str(circ_avg))

    if not cs_junk.group_by_class:
      # FIXME: This may be expensive
      pid_avg = filt_avg
      prev_pid_avg = 2*pid_avg
      f_nodes = nodes.values()

      while prev_pid_avg > pid_avg:
        f_nodes = filter(lambda n: n.desc_bw >= pid_avg, f_nodes)
        prev_pid_avg = pid_avg
        pid_avg = sum(map(lambda n: n.filt_bw, f_nodes))/float(len(f_nodes))

      for cl in ["Guard+Exit", "Guard", "Exit", "Middle"]:
        true_filt_avg[cl] = filt_avg
        true_strm_avg[cl] = strm_avg
        true_circ_avg[cl] = circ_avg
        pid_tgt_avg[cl] = pid_avg

      plog("INFO", "Network pid_avg: "+str(pid_avg))

  else:
    plog("INFO", "PID control disabled")
    filt_avg = sum(map(lambda n: n.filt_bw, nodes.itervalues()))/float(len(nodes))
    strm_avg = sum(map(lambda n: n.strm_bw, nodes.itervalues()))/float(len(nodes))
    for cl in ["Guard+Exit", "Guard", "Exit", "Middle"]:
      true_filt_avg[cl] = filt_avg
      true_strm_avg[cl] = strm_avg


  prev_votes = None
  if cs_junk.bwauth_pid_control:
    prev_votes = VoteSet(argv[-1])

    guard_cnt = 0
    node_cnt = 0
    guard_measure_time = 0
    node_measure_time = 0
    for n in nodes.itervalues():
      if n.idhex in prev_votes.vote_map and n.idhex in prev_consensus:
        if "Guard" in prev_consensus[n.idhex].flags and \
           "Exit" not in prev_consensus[n.idhex].flags:
          if n.measured_at != prev_votes.vote_map[n.idhex].measured_at:
            guard_cnt += 1
            guard_measure_time += (n.measured_at - \
                                    prev_votes.vote_map[n.idhex].measured_at)
        else:
          if n.updated_at != prev_votes.vote_map[n.idhex].updated_at:
            node_cnt += 1
            node_measure_time += (n.updated_at - \
                                  prev_votes.vote_map[n.idhex].updated_at)

    # TODO: We may want to try to use this info to autocompute T_d and
    # maybe T_i?
    if node_cnt > 0:
      plog("INFO", "Avg of "+str(node_cnt)+" node update intervals: "+str((node_measure_time/node_cnt)/3600.0))

    if guard_cnt > 0:
      plog("INFO", "Avg of "+str(guard_cnt)+" guard measurement interval: "+str((guard_measure_time/guard_cnt)/3600.0))

  tot_net_bw = 0
  for n in nodes.itervalues():
    n.fbw_ratio = n.filt_bw/true_filt_avg[n.node_class()]
    n.sbw_ratio = n.strm_bw/true_strm_avg[n.node_class()]

    if cs_junk.bwauth_pid_control:
      if cs_junk.use_desc_bw:
        n.use_bw = n.desc_bw
      else:
        n.use_bw = n.ns_bw

      if cs_junk.use_pid_tgt:
          n.pid_error = (n.strm_bw - pid_tgt_avg[n.node_class()]) \
                           / pid_tgt_avg[n.node_class()]
          # use filt_bw for pid_error < 0
          if cs_junk.use_mercy:
            if cs_junk.use_desc_bw:
              if n.pid_error_sum < 0 and n.pid_error < 0:
                n.pid_error = (n.filt_bw - pid_tgt_avg[n.node_class()]) \
                           / pid_tgt_avg[n.node_class()]
            else:
              if n.desc_bw > n.ns_bw and n.pid_error < 0:
                n.pid_error = (n.filt_bw - pid_tgt_avg[n.node_class()]) \
                           / pid_tgt_avg[n.node_class()]
      else:
        if cs_junk.use_best_ratio and n.sbw_ratio > n.fbw_ratio:
          n.pid_error = (n.strm_bw - true_strm_avg[n.node_class()]) \
                           / true_strm_avg[n.node_class()]
        else:
          n.pid_error = (n.filt_bw - true_filt_avg[n.node_class()]) \
                           / true_filt_avg[n.node_class()]

      # XXX: Refactor the following 3 clauses out into it's own function, so we can log
      # only in the event of update?
      # Penalize nodes for circ failure rate
      if cs_junk.use_circ_fails:
        # Compute circ_error relative to 1.0 (full success), but only
        # apply it if it is both below the network avg and worse than
        # the pid_error
        if (1.0-n.circ_fail_rate) < true_circ_avg[n.node_class()]:
          circ_error = -n.circ_fail_rate # ((1.0-fail) - 1.0)/1.0
          if circ_error < 0 and circ_error < n.pid_error:
            plog("INFO",
              "CPU overload for %s node %s=%s desc=%d ns=%d pid_error=%f circ_error=%f circ_fail=%f" %
              (n.node_class(), n.nick, n.idhex, n.desc_bw, n.ns_bw,
               n.pid_error, circ_error, n.circ_fail_rate))
            n.pid_error = min(circ_error,n.pid_error)

      # Don't accumulate too much amplification for fast nodes
      if cs_junk.use_desc_bw:
        if n.pid_error_sum > cs_junk.pid_max and n.pid_error > 0:
          plog("INFO", "Capping feedback for %s node %s=%s desc=%d ns=%d pid_error_sum=%f" %
              (n.node_class(), n.nick, n.idhex, n.desc_bw, n.ns_bw, n.pid_error_sum))
          n.pid_error_sum = cs_junk.pid_max
      else:
        if float(n.ns_bw)/n.desc_bw > cs_junk.pid_max and n.pid_error > 0:
          plog("INFO", "Capping feedback for %s node %s=%s desc=%d ns=%d pid_error=%f" %
              (n.node_class(), n.nick, n.idhex, n.desc_bw, n.ns_bw, n.pid_error))
          n.pid_error = 0
          n.pid_error_sum = 0

      # Don't punish gimpy nodes too hard.
      if cs_junk.use_mercy:
        if not cs_junk.use_desc_bw:
          # If node was demoted in the past and we plan to demote it again,
          # let's just not and say we did.
          if n.desc_bw > n.ns_bw and n.pid_error < 0:
            plog("DEBUG", "Showing mercy for %s node %s=%s desc=%d ns=%d pid_error=%f" %
                 (n.node_class(), n.nick, n.idhex, n.desc_bw, n.ns_bw, n.pid_error))
            n.use_bw = n.desc_bw
        if n.pid_error_sum < 0 and n.pid_error < 0:
          plog("DEBUG", "Showing mercy for %s node %s=%s desc=%d ns=%d pid_error_sum=%f" %
              (n.node_class(), n.nick, n.idhex, n.desc_bw, n.ns_bw, n.pid_error_sum))
          n.pid_error_sum = 0

      if n.idhex in prev_votes.vote_map:
        # If there is a new sample, let's use it for all but guards
        if n.measured_at > prev_votes.vote_map[n.idhex].measured_at:

          # Nodes with the Guard flag will respond slowly to feedback,
          # so they should be sampled less often, and in proportion to
          # the appropriate Wgx weight.
          if n.idhex in prev_consensus and \
            ("Guard" in prev_consensus[n.idhex].flags \
             and "Exit" not in prev_consensus[n.idhex].flags):
            # Do full feedback if our previous vote > 2.5 weeks old
            if n.idhex not in prev_votes.vote_map or \
                n.measured_at - prev_votes.vote_map[n.idhex].measured_at \
                    > cs_junk.guard_sample_rate:
              n.new_bw = n.get_pid_bw(prev_votes.vote_map[n.idhex],
                                      cs_junk.K_p,
                                      cs_junk.K_i,
                                      cs_junk.K_d,
                                      cs_junk.K_i_decay)
            else:
              # Don't use feedback here, but we might as well use our
              # new measurement against the previous vote.
              n.copy_vote(prev_votes.vote_map[n.idhex])

              if cs_junk.use_desc_bw:
                n.new_bw = n.get_pid_bw(prev_votes.vote_map[n.idhex],
                                    cs_junk.K_p,
                                    cs_junk.K_i,
                                    cs_junk.K_d,
                                    0.0, False)
              else:
                # Use previous vote's feedback bw
                # FIXME: compare to ns_bw or prev_vote bw?
                if cs_junk.use_mercy and n.desc_bw > n.ns_bw and n.pid_error < 0:
                  n.use_bw = n.desc_bw
                else:
                  n.use_bw = prev_votes.vote_map[n.idhex].pid_bw
                n.new_bw = n.get_pid_bw(prev_votes.vote_map[n.idhex],
                                    cs_junk.K_p,
                                    0.0,
                                    0.0,
                                    0.0, False)

              # Reset the remaining vote data..
              n.measured_at = prev_votes.vote_map[n.idhex].measured_at
              n.pid_error = prev_votes.vote_map[n.idhex].pid_error
          else:
            # Everyone else should be pretty instantenous to respond.
            # Full feedback should be fine for them (we hope),
            # except for Guard+Exits, we want to dampen just a little
            # bit for them. Wgd seems a good choice, but might not be exact.
            # We really want to magically combine Wgd and something that
            # represents the client migration rate for Guards.. But who
            # knows how to represent that and still KISS?
            if n.idhex in prev_consensus and \
              ("Guard" in prev_consensus[n.idhex].flags \
               and "Exit" in prev_consensus[n.idhex].flags):
              # For section2-equivalent mode and/or use_mercy, we should
              # not use Wgd
              if n.use_bw == n.desc_bw:
                weight = 1.0
              else:
                weight = (1.0-cs_junk.bw_weights["Wgd"])
              n.new_bw = n.get_pid_bw(prev_votes.vote_map[n.idhex],
                              cs_junk.K_p*weight,
                              cs_junk.K_i*weight,
                              cs_junk.K_d*weight,
                              cs_junk.K_i_decay)
            else:
              n.new_bw = n.get_pid_bw(prev_votes.vote_map[n.idhex],
                              cs_junk.K_p,
                              cs_junk.K_i,
                              cs_junk.K_d,
                              cs_junk.K_i_decay)
        else:
          # Reset values. Don't vote/sample this measurement round.
          n.revert_to_vote(prev_votes.vote_map[n.idhex])
      else: # No prev vote, pure consensus feedback this round
        n.new_bw = n.use_bw + cs_junk.K_p*n.use_bw*n.pid_error
        n.pid_error_sum = n.pid_error
        n.pid_bw = n.new_bw
        plog("DEBUG", "No prev vote for node "+n.nick+": Consensus feedback")
    else: # No PID feedback
      # Choose the larger between sbw and fbw
      if n.sbw_ratio > n.fbw_ratio:
        n.ratio = n.sbw_ratio
      else:
        n.ratio = n.fbw_ratio

      n.pid_error = 0
      n.pid_error_sum = 0
      n.new_bw = n.desc_bw*n.ratio
      n.pid_bw = n.new_bw # for transition between pid/no-pid

    n.change = n.new_bw - n.desc_bw

    if n.idhex in prev_consensus:
      if prev_consensus[n.idhex].bandwidth != None:
        prev_consensus[n.idhex].measured = True
        tot_net_bw += n.new_bw
      if IGNORE_GUARDS \
           and ("Guard" in prev_consensus[n.idhex].flags and not "Exit" in \
                  prev_consensus[n.idhex].flags):
        plog("INFO", "Skipping voting for guard "+n.nick)
        n.ignore = True
      elif "Authority" in prev_consensus[n.idhex].flags:
        plog("DEBUG", "Skipping voting for authority "+n.nick)
        n.ignore = True

  # Go through the list and cap them to NODE_CAP
  for n in nodes.itervalues():
    if n.new_bw >= 0x7fffffff:
      plog("WARN", "Bandwidth of "+n.node_class()+" node "+n.nick+"="+n.idhex+" exceeded maxint32: "+str(n.new_bw))
      n.new_bw = 0x7fffffff
    if cs_junk.T_i > 0 and cs_junk.T_i_decay > 0 \
       and math.fabs(n.pid_error_sum) > \
           math.fabs(2*cs_junk.T_i*n.pid_error/cs_junk.T_i_decay):
      plog("NOTICE", "Large pid_error_sum for node "+n.idhex+"="+n.nick+": "+
                   str(n.pid_error_sum)+" vs "+str(n.pid_error))
    if n.new_bw > tot_net_bw*NODE_CAP:
      plog("INFO", "Clipping extremely fast "+n.node_class()+" node "+n.idhex+"="+n.nick+
           " at "+str(100*NODE_CAP)+"% of network capacity ("+
           str(n.new_bw)+"->"+str(int(tot_net_bw*NODE_CAP))+") "+
           " pid_error="+str(n.pid_error)+
           " pid_error_sum="+str(n.pid_error_sum))
      n.new_bw = int(tot_net_bw*NODE_CAP)
      n.pid_error_sum = 0 # Don't let unused error accumulate...
    if n.new_bw <= 0:
      if n.idhex in prev_consensus:
        plog("INFO", n.node_class()+" node "+n.idhex+"="+n.nick+" has bandwidth <= 0: "+str(n.new_bw))
      else:
        plog("INFO", "New node "+n.idhex+"="+n.nick+" has bandwidth < 0: "+str(n.new_bw))
      n.new_bw = 1

  oldest_measured = min(map(lambda n: n.measured_at,
             filter(lambda n: n.idhex in prev_consensus,
                       nodes.itervalues())))
  plog("INFO", "Oldest measured node: "+time.ctime(oldest_measured))

  oldest_updated = min(map(lambda n: n.updated_at,
             filter(lambda n: n.idhex in prev_consensus,
                       nodes.itervalues())))
  plog("INFO", "Oldest updated node: "+time.ctime(oldest_updated))

  missed_nodes = 0.0
  missed_bw = 0
  tot_bw = 0
  for n in prev_consensus.itervalues():
    if n.bandwidth != None:
      tot_bw += n.bandwidth
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
          if n.bandwidth == None:
            missed_bw += r.bw
          else:
            missed_bw += n.bandwidth
          # We still tend to miss about 80 nodes even with these
          # checks.. Possibly going in and out of hibernation?
          plog("DEBUG", "Didn't measure "+n.idhex+"="+n.nickname+" at "+str(round((100.0*n.list_rank)/max_rank,1))+" "+str(n.bandwidth))

  measured_pct = round(100.0*len(nodes)/(len(nodes)+missed_nodes),1)
  measured_bw_pct = 100.0 - round((100.0*missed_bw)/tot_bw,1)
  if measured_pct < MIN_REPORT:
    plog("NOTICE", "Did not measure "+str(MIN_REPORT)+"% of nodes yet ("+str(measured_pct)+"%)")
    sys.exit(1)

  # Notification hack because #2286/#4359 is annoying arma
  if measured_bw_pct < 75:
    plog("WARN",
         "Only measured %f of the previous consensus bandwidth despite measuring %f of the nodes" %
         (measured_bw_pct, measured_pct))
  elif measured_bw_pct < 95:
    plog("NOTICE",
         "Only measured %f of the previous consensus bandwidth despite measuring %f of the nodes" %
         (measured_bw_pct, measured_pct))

  for cl in ["Guard+Exit", "Guard", "Exit", "Middle"]:
    c_nodes = filter(lambda n: n.node_class() == cl, nodes.itervalues())
    nc_nodes = filter(lambda n: n.pid_error < 0, c_nodes)
    pc_nodes = filter(lambda n: n.pid_error > 0, c_nodes)
    if len(c_nodes) > 0:
      plog("INFO", "Avg "+cl+"  pid_error="+str(sum(map(lambda n: n.pid_error, c_nodes))/len(c_nodes)))
      plog("INFO", "Avg "+cl+" |pid_error|="+str(sum(map(lambda n: abs(n.pid_error), c_nodes))/len(c_nodes)))
    if len(pc_nodes) > 0:
      plog("INFO", "Avg "+cl+" +pid_error=+"+str(sum(map(lambda n: n.pid_error, pc_nodes))/len(pc_nodes)))
    if len(nc_nodes) > 0:
      plog("INFO", "Avg "+cl+" -pid_error="+str(sum(map(lambda n: n.pid_error, nc_nodes))/len(nc_nodes)))

  n_nodes = filter(lambda n: n.pid_error < 0, nodes.itervalues())
  p_nodes = filter(lambda n: n.pid_error > 0, nodes.itervalues())
  plog("INFO", "Avg network  pid_error="+str(sum(map(lambda n: n.pid_error, nodes.itervalues()))/len(nodes)))
  plog("INFO", "Avg network |pid_error|="+str(sum(map(lambda n: abs(n.pid_error), nodes.itervalues()))/len(nodes)))
  plog("INFO", "Avg network +pid_error=+"+str(sum(map(lambda n: n.pid_error, p_nodes))/len(p_nodes)))
  plog("INFO", "Avg network -pid_error="+str(sum(map(lambda n: n.pid_error, n_nodes))/len(n_nodes)))


  plog("NOTICE",
       "Measured "+str(measured_pct) +"% of all tor nodes ("
       +str(measured_bw_pct)+"% of previous consensus bw).")

  n_print = nodes.values()
  n_print.sort(lambda x,y: int(y.pid_error*1000) - int(x.pid_error*1000))

  scan_age = 0
  for scanner in scanner_timestamps.iterkeys():
    this_scan_age = int(round(scanner_timestamps[scanner],0))
    scan_age = scan_age if scan_age > this_scan_age else this_scan_age
    if this_scan_age < time.time() - MAX_SCAN_AGE:
      plog("WARN", "Bandwidth scanner "+scanner+" stale. Possible dead bwauthority.py. Timestamp: "+time.ctime(this_scan_age))

  out = file(argv[-1], "w")
  out.write(str(scan_age)+"\n")

  # FIXME: Split out debugging data
  for n in n_print:
    if not n.ignore:
      # Turns out str() is more accurate than %lf
      out.write("node_id="+n.idhex+" bw="+str(base10_round(n.new_bw))+" nick="+n.nick+ " measured_at="+str(int(n.measured_at))+" updated_at="+str(int(n.updated_at))+" pid_error="+str(n.pid_error)+" pid_error_sum="+str(n.pid_error_sum)+" pid_bw="+str(int(n.pid_bw))+" pid_delta="+str(n.pid_delta)+" circ_fail="+str(n.circ_fail_rate)+" scanner="+str(n.scanner)+"\n")
  out.close()

  write_file_list(argv[1])

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
