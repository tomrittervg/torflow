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
import math

def CalculateTimeout(Xm, alpha, q):
  return (Xm/math.pow(1.0-q,1.0/alpha))/1000.0;

sample_sizes = [100, 150, 200, 250, 300, 350, 400, 500, 600, 800, 1000]

def dump_table(Xm, alpha):
  for n in sample_sizes:
    sigma = alpha/math.sqrt(n)
    print "Timeouts for Xm: "+str(Xm)+", alpha: "+str(alpha)+" n:"+str(n)+" sigma: "+str(sigma)
    print "\t -2*sigma: "+str(CalculateTimeout(Xm, alpha-2*sigma, .8))
    print "\t -1*sigma: "+str(CalculateTimeout(Xm, alpha-sigma, .8))
    print "\t  0*sigma: "+str(CalculateTimeout(Xm, alpha, .8))
    print "\t +1*sigma: "+str(CalculateTimeout(Xm, alpha-1*sigma, .8))
    print "\t +2*sigma: "+str(CalculateTimeout(Xm, alpha-2*sigma, .8))

dump_table(1950, 1.4)
print
print
dump_table(975, 0.9)



