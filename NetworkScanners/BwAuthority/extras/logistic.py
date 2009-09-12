#!/usr/bin/python

import math

# From http://en.wikipedia.org/wiki/Logistic_distribution#Quantile_function
# Q(p) = u + s*ln(p/(1-p))
# We want to solve for u and s. So we want a linear regression to solve:
# time = u + s*ln(upgrade_rate/(1-upgrade_rate))

# http://en.wikipedia.org/wiki/Simple_linear_regression#Fitting_the_regression_line
# So u=> Alpha; s=>Beta and x=>ln(upgrade_rate/(1-upgrade_rate))
# and time => y

def estimate(upgrade_table):
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

  return (u,s)

