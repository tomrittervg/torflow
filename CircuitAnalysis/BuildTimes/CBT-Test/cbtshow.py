#!/usr/bin/python

import os
import sys
import re

# Stats:
# Pct Avg
#   0. MIN_CIRCS
#   1. NUM_CIRCS
#   2. NUM_TIMEOUT
# Overall Avg (weighted)
#   2. BUILD_RATE

# Recompute:
#  Build rate +/- 1 second, +/- 2 second

def walk_single_pct(pct_dir):
  built_succeed_tot = 0
  built_tot = 0
  avg_min_circs = 0
  avg_num_circs = 0
  avg_num_timeout = 0
  reset_test_cnt = 0
  avg_reset_cnt = 0
  res_count = 0

  for pct_root, pct_dirs, pct_files in os.walk(pct_dir):
    for pct_run in pct_dirs:
      for run_root, dirs, files in os.walk(pct_dir+"/"+pct_run):
        for ds in dirs:
          if re.match("^redo.[\d+]$", ds):
            for sr, sd, sf in os.walk(pct_dir+"/"+pct_run+"/"+ds):
              for f in sf:
                if f == "result":
                  r = open(pct_dir+"/"+pct_run+"/"+ds+"/"+f)
                  for l in r.readlines():
                    bg = re.match("^BUILD_RATE\: ([\d]+)/([\d]+)", l)
                    if bg: built,total = map(int, bg.groups())
                    ncg = re.match("^NUM_CIRCS\: ([\d]+)", l)
                    if ncg: num_circs = int(ncg.groups()[0])
                    ntg = re.match("^NUM_TIMEOUT\: ([\d]+)", l)
                    if ntg: num_timeout = int(ntg.groups()[0])
                    rcg = re.match("^RESET_CNT\: ([\d]+)", l)
                    if rcg: reset_cnt = int(rcg.groups()[0])
          
                  avg_reset_cnt += reset_cnt
                  reset_test_cnt += 1
                  
                  if built <= 0 or num_circs <= 0 or num_timeout <= 0:
                    print "Skipping -1 file in "+pct_root+pct_run
                    continue

                  built_succeed_tot += built
                  built_tot += total
              if built <= 0 or num_circs <= 0 or num_timeout <= 0:
                continue

              # XXX: Hrmm..
              for f in sf:
                if f == "buildtimes":
                  counts = [0,0,0,0]

        for f in files:
          if f == "result":
            r = open(pct_root+"/"+pct_run+"/"+f)
            res_count += 1
            for l in r.readlines():
              bg = re.match("^BUILD_RATE\: ([\d]+)/([\d]+)", l)
              if bg: built,total = map(int, bg.groups())
              ncg = re.match("^NUM_CIRCS\: ([\d]+)", l)
              if ncg: num_circs = int(ncg.groups()[0])
              ntg = re.match("^NUM_TIMEOUT\: ([\d]+)", l)
              if ntg: num_timeout = int(ntg.groups()[0])
              mcg = re.match("^MIN_CIRCS\: ([\d]+)", l)
              if mcg: min_circs = int(mcg.groups()[0])
              rcg = re.match("^RESET_CNT\: ([\d]+)", l)
              if rcg: reset_cnt = int(rcg.groups()[0])

            # Only count resets for redo runs 
            #avg_reset_cnt += reset_cnt
            #reset_test_cnt += 1
               
            if built <= 0 or min_circs <= 0 or num_circs <= 0 \
                 or num_timeout <= 0:
              print "Skipping -1 file in "+pct_root+pct_run
              continue
           
            # Only count build_rate from redo runs
            #built_succeed_tot += built
            #built_tot += total

            avg_min_circs += min_circs
            avg_num_circs += num_circs
            avg_num_timeout += num_timeout

  avg_min_circs /= float(res_count)
  avg_num_circs /= float(res_count)
  avg_num_timeout /= float(res_count)
  avg_reset_cnt /= float(reset_test_cnt)

  print "Avg Min Circs: "+str(avg_min_circs)
  print "Avg Num Circs: "+str(avg_num_circs)
  print "Avg Num Timeout: "+str(avg_num_timeout)
  print "Avg Reset Cnt: "+str(avg_reset_cnt)
  print str(built_succeed_tot)+"/"+str(built_tot)+"="+str(float(built_succeed_tot)/built_tot)


def main():
  walk_single_pct(sys.argv[1])

main()


