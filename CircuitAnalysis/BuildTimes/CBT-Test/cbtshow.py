#!/usr/bin/python

import os
import sys
import re
import math

# Stats:
# Pct Avg
#   0. MIN_CIRCS
#   1. NUM_CIRCS
#   2. NUM_TIMEOUT
# Overall Avg (weighted)
#   2. BUILD_RATE

# Recompute:
#  Build rate +/- 1 second, +/- 2 second

def min_avg_max_dev(ls):
  ls_len = len(ls)
  avg = float(sum(ls))/ls_len
  mn = min(ls)
  mx = max(ls)
  dev = 0.0

  for l in ls: dev += (l-avg)*(l-avg)

  dev /= float(ls_len-1.0)
  dev = math.sqrt(dev)
  
  ret = map(lambda x: round(x, 2), [mn, avg, mx, dev])
  #return str(ret)
  return "\t"+"/".join(map(str, ret)) #+"\t(min/avg/max/dev)"


def walk_single_pct(pct_dir):
  built_succeed_tot = 0
  built_tot = 0
  redo_built_rates = []
  redo_resets = []
  min_resets = []
  num_resets = []
  min_circs = []
  num_circs = []
  num_timeouts = []
  min_timeouts = []

  for pct_root, pct_dirs, pct_files in os.walk(pct_dir):
    for pct_run in pct_dirs:
      for run_root, dirs, files in os.walk(pct_dir+"/"+pct_run):
        for ds in dirs:
          if re.match("^redo.[\d+]$", ds):
            for sr, sd, sf in os.walk(pct_dir+"/"+pct_run+"/"+ds):
              built = num_circ = num_timeout = 0
              for f in sf:
                if f == "result":
                  r = open(pct_dir+"/"+pct_run+"/"+ds+"/"+f)
                  for l in r.readlines():
                    bg = re.match("^BUILD_RATE\: ([\d]+)/([\d]+)", l)
                    if bg: built,total = map(int, bg.groups())
                    ncg = re.match("^NUM_CIRCS\: ([\d]+)", l)
                    if ncg: num_circ = int(ncg.groups()[0])
                    ntg = re.match("^NUM_TIMEOUT\: ([\d]+)", l)
                    if ntg: num_timeout = int(ntg.groups()[0])
                    rcg = re.match("^NUM_RESET_CNT\: ([\d]+)", l)
                    if rcg: reset_cnt = int(rcg.groups()[0])
         
                  redo_resets.append(reset_cnt)
                  
                  if built <= 0 or num_circ <= 0 or num_timeout <= 0:
                    print "Skipping -1 redo file in "+pct_root+"/"+pct_run+"/"+ds+"/"+f
                    continue

                  built_succeed_tot += built
                  built_tot += total
                  redo_built_rates.append(float(built)/total)
              if built <= 0 or num_circ <= 0 or num_timeout <= 0:
                continue


        for f in files:
          if f == "result":
            r = open(pct_root+"/"+pct_run+"/"+f)
            for l in r.readlines():
              bg = re.match("^BUILD_RATE\: ([\d]+)/([\d]+)", l)
              if bg: built,total = map(int, bg.groups())
              ncg = re.match("^NUM_CIRCS\: ([\d]+)", l)
              if ncg: num_circ = int(ncg.groups()[0])
              ntg = re.match("^NUM_TIMEOUT\: ([\d]+)", l)
              if ntg: num_timeout = int(ntg.groups()[0])
              mcg = re.match("^MIN_CIRCS\: ([\d]+)", l)
              if mcg: min_circ = int(mcg.groups()[0])
              rcg = re.match("^NUM_RESET_CNT\: ([\d]+)", l)
              if rcg: num_reset_cnt = int(rcg.groups()[0])
              rcg = re.match("^MIN_RESET_CNT\: ([\d]+)", l)
              if rcg: min_reset_cnt = int(rcg.groups()[0])
              ntg = re.match("^MIN_TIMEOUT\: ([\d]+)", l)
              if ntg: min_timeout = int(ntg.groups()[0])
 

            num_resets.append(num_reset_cnt)
            min_resets.append(min_reset_cnt)
               
            if built <= 0 or min_circ <= 0 or num_circ <= 0 \
                 or num_timeout <= 0:
              print "Skipping -1 file in "+pct_root+"/"+pct_run+"/"+f
              continue
           
            min_circs.append(min_circ)
            min_timeouts.append(min_timeout)
            num_circs.append(num_circ)
            num_timeouts.append(num_timeout)


  print "Result type\tmin/avg/max/dev"
  print "-----------\t---------------"
  print "Fuzzy Circs: "+min_avg_max_dev(min_circs)
  print "Fuzzy Timeout: "+min_avg_max_dev(min_timeouts)
  print "Fuzzy Resets: "+min_avg_max_dev(min_resets)
  print "Full Circs: "+min_avg_max_dev(num_circs)
  print "Full Timeout: "+min_avg_max_dev(num_timeouts)
  print "Full Resets: "+min_avg_max_dev(num_resets)
  print "Redo Resets: "+min_avg_max_dev(redo_resets)
  print "Built Rates: "+min_avg_max_dev(redo_built_rates)
  print "Built Rate Weighted Avg: "+str(built_succeed_tot)+"/"+str(built_tot)+"="+str(float(built_succeed_tot)/built_tot)


def main():
  walk_single_pct(sys.argv[1])

if __name__ == "__main__":
  main()


