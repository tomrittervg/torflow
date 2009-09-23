#!/usr/bin/python
#
# Experiment with pareto distribution to get an idea on what the expected
# error on alpha will do to our timeout value.
#
# http://en.wikipedia.org/wiki/Pareto_distribution#Parameter_estimation
#
# Note that alpha is not the only potential source of estimate error though.
# With insufficient samples we may not have a valid value for Xm either.
# I'm uncertain at this point on how to account for this or bound this error.
#
# One other thing to note is the possible interplay with the CDF point
# and the values from binomial.py
import math

def CalculateTimeout(Xm, alpha, q):
  return (Xm/math.pow(1.0-q,1.0/alpha))/1000.0;

def ParetoF(Xm, alpha, timeout):
  return math.pow(Xm/timeout, alpha)

sample_sizes = [50, 100, 250, 500, 1000, 2500, 5000]

def dump_table(Xm, alpha):
  for n in sample_sizes:
    sigma = alpha/math.sqrt(n)
    print "Timeouts for Xm: "+str(Xm)+", alpha: "+str(alpha)+" n="+str(n)+" sigma: "+str(sigma)
    t=CalculateTimeout(Xm, alpha-2*sigma, .8)
    print "\t -2*sigma: "+str(round(t,1))+" timeout %="+str(round(100*ParetoF(Xm, alpha, t*1000),1))
    t=CalculateTimeout(Xm, alpha-1*sigma, .8)
    print "\t -1*sigma: "+str(round(t,1))+" timeout %="+str(round(100*ParetoF(Xm, alpha, t*1000),1))
    t=CalculateTimeout(Xm, alpha, .8)
    print "\t  0*sigma: "+str(round(t,1))+" timeout %="+str(round(100*ParetoF(Xm, alpha, t*1000),1))
    t=CalculateTimeout(Xm, alpha+1*sigma, .8)
    print "\t +1*sigma: "+str(round(t,1))+" timeout %="+str(round(100*ParetoF(Xm, alpha, t*1000),1))
    t=CalculateTimeout(Xm, alpha+2*sigma, .8)
    print "\t +2*sigma: "+str(round(t,1))+" timeout %="+str(round(100*ParetoF(Xm, alpha, t*1000),1))


dump_table(1950, 1.4)
print
print
dump_table(975, 0.9)



