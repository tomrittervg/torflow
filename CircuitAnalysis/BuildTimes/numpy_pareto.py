#!/usr/bin/python
import numpy
import pylab
import matplotlib


def loadbuildtimes():
  f = open('40k_r1/45-50.40000.buildtimes')
  vals = []
  for line in f:
    line = line.split('\t')
    vals += [float(line[1].strip())*1000]
  vals.sort()
  vals.reverse()
  return vals

    
def pareto(x,k,Xm):
  return k*(Xm**k)/(x**(k+1))

#get buildtime data (in ms)
Z = loadbuildtimes()

# plot histogram.
# args: values, number of bins, normalize y/n, width of bars

pylab.hist(Z,len(Z) / 100.0, normed=True, width=5)

#pareto parameters (taken from output of ./shufflebt.py buildtimes)
#Resolution of histogram: 100 ms
#Mean: 5746.8020777, mode: 1600
#ParK: 0.918058347945
#ModeN: 32775 vs integrated: 32394.9483089
#successful runs: 41712

k = 0.687880881456 
Xm = 1800
n = 28921


# args to a range: x start, x end 
X = pylab.arange(Xm, max(Z), 1) # max(Z), 0.1)    # x values from  1 to max(Z) in increments of 0.1 (can adjust this to look at different parts of the graph)
Y = map(lambda x: pareto(x,k,Xm), X) #pareto(x) (units: #measurements with value x)

# verify sanity by integrating scaled distribution:
modeNint = numpy.trapz(map(lambda x: n*pareto(x, k, Xm),
                 xrange(Xm,200000)))

print modeNint

print n*pareto(Xm, k, Xm)

#draw pareto curve
# X values plotted against Y values, will appear as blue circles b:blue o:circle
pylab.plot(X,Y,'b-')

#save figure
pylab.savefig('paretofig.png')

