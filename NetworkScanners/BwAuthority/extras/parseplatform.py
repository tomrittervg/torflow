#!/usr/bin/python

# Parses metrics.git/out/dirarch/platforms.csv and estimates logistic
# distribution parameters based on this data.

import time
import logistic

f = open("platforms.csv", "r")
f.readline()

upgrade_table = {}
t0 = 0
for l in f.readlines():
  v = l.split(",")
  if v[5] == "NA" or int(v[5]) == 0: continue
  up = (float(v[5])+float(v[6])+float(v[7]))/float(v[8])
  t = time.mktime(time.strptime(v[0], "%Y-%m-%d"))
  if t0 == 0: t0 = t
  upgrade_table[t-t0] = up


(u,s) = logistic.estimate(upgrade_table)

print "s="+str(s)+", u="+str(u)
print "Estimate 50% upgrade at: "+time.ctime(t0+u)
