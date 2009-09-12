#!/usr/bin/python

# Parses metrics.git/out/dirarch/platforms.csv and estimates logistic
# distribution parameters based on this data.

import time
import math

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



# From http://en.wikipedia.org/wiki/Logistic_distribution#Quantile_function
# Q(p) = u + s*ln(p/(1-p))
# We want to solve for u and s. So we want a linear regression to solve:
# time = u + s*ln(upgrade_rate/(1-upgrade_rate))

# http://en.wikipedia.org/wiki/Simple_linear_regression#Fitting_the_regression_line
# So u=> Alpha; s=>Beta and x=>ln(upgrade_rate/(1-upgrade_rate))
# and time => y

y = {}
for t in upgrade_table.iterkeys():
  x = math.log(upgrade_table[t]/(1.0-upgrade_table[t]))
  y[x] = t


y_ = sum(y.itervalues())/len(y)
x_ = sum(y.iterkeys())/len(y)

xy__ = sum(map(lambda x: x*y[x], y.iterkeys()))/len(y)

x2_ = sum(map(lambda x: x*x, y.iterkeys()))/len(y)

s = Beta = (xy__ - x_*y_)/(x2_ - x_*x_)

u = Alpha = y_ - Beta*x_


print "s="+str(s)+", u="+str(u)

print "Estimate 50% upgrade at: "+time.ctime(t0+u)
