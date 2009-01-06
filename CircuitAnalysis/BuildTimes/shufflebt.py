#!/usr/bin/env python
# shufflebt.py
# (c) Fallon Chen 2008
# Shuffles a list of  build times and produces a pdf of n of those buildtimes, 
# which are put into res (defaults to 100)ms blocks.
# Requires gnuplot 4.2 and a version coreutils that provides sort -R 
# "usage: shufflebt.py [-n <number of circuits>] [-s] [-g] [-k <k value>] [-d outdirname] <list of filenames>"
# if outdir is not specified, the script will write files to the current directory
# if a directory is given instead of a list of filenames, all files postfixed with '.buildtimes' will be processed
import getopt,sys,os
import popen2
import math,copy
from scipy.integrate import *
from numpy import trapz
import numpy
import pylab
import matplotlib

class Stats:
  def __init__(self,file):
    self.f = open(file)
    self.values = []
    for line in self.f:
      line = line.split('\t')
      self.values += [float(line[1]) * 1000]
      
    self.f.close()
    self.buckets = {}
  def mean(self):
    # Borrowed from TorUtil
    if len(self.values) > 0:
      sum = reduce(lambda x,y: x+y,self.values,0.0)
      return sum/len(self.values)
    else:
      return 0.0
  def stddev(self):
    # Borrowed from TorUtil
    if len(self.values) > 1:
      mean = self.mean()
      sum = reduce(lambda x,y: x + ((y-mean)**2.0),self.values,0.0)
      s = math.sqrt(sum/(len(self.values)-1))
      return s
    else:
      return 0.0
  def median(self):
    if len(self.values) > 0:
      values = copy.copy(self.values)
      values.sort()
      return values[(len(values) - 1)/2]
    else:
      return 0.0

  def mode(self): # Requires makehistogram runs first
    counts = {}
    greatest_val = 0
    greatest_idx = 0
    for v in self.buckets.keys():
      if self.buckets[v] > greatest_val:
        greatest_idx = v
        greatest_val = self.buckets[v]
    return greatest_idx


  def pyhist(self,res,histname):
    bins = len(self.values) / res
    print 'bins:',bins
    x = matplotlib.numerix.arange(1,7000, 0.01)
    S = pypareto(x,0.918058347945, 1600.0, 32775.0)
    #pylab.hist(self.values,bins=bins,normed=False, width=1)
    #(n,bins) = numpy.histogram(self.values,bins=bins,normed=False)
    #pylab.plot(bins,n  )
    pylab.plot(x,S, 'bo')
    #pylab.show()
    pylab.savefig(histname + '.png')

  # XXX: This doesn't seem to work for small #s of circuits  
  def makehistogram(self,res,histname):
    #res = res /1000.0 # convert ms to s
    values = copy.copy(self.values) 
    values.sort()
    count = 0
    i = 1
    self.buckets = {} 
    for v in values:
      if v < res * i: count += 1
      else:
        count += 1
        self.buckets[int(res * i)] = count
        #self.buckets[int(res * i * 10)] = count
        i += 1
        count = 0
    f = open(histname,'w')
    f.write('#build time <\t#circuits\n')
    sortedkeys = self.buckets.keys()
    sortedkeys.sort()
    for b in sortedkeys:
      towrite = str(b) + '\t' + str(self.buckets[b]) + '\n'
      f.write(towrite)
    f.close()
  
  def paretoK(self, Xm):
    n = 0
    log_sum = 0
    X = min(self.values)
    for x in self.values:
      if x < Xm: continue
      n += 1
      log_sum += math.log(x)
    return n/(log_sum - n*math.log(Xm))

  # Calculate the mean beyond a mode value
  def modeMean(self, Xm):
    n = 0
    tot = 0
    for x in self.values:
      if x < Xm: continue
      n += 1
      tot += x
    return tot/n

  def modeN(self, Xm):
    n = 0
    for x in self.values:
      if x < Xm: continue
      n += 1
    return n

  def maxlikelihood(self,k):
    # theta estimator for gamma PDF
    # maxlikelihood estimator
    # theta = sum(values) / N*k 
    return 10*sum(self.values)/(k * len(self.values))

  def bayesian(self,k):
    # bayesian estimator for gamma PDF
    # y = sum(values)
    # theta = y/(Nk - 1) +/- y^2/((Nk-1)^2(Nk -2))
    y = sum(self.values) * 10
    N = len(self.values)
    mean = y/(N*k - 1)
    sdev = (y*y)/((N*k - 1)* (N*k - 1) * (N*k - 2))
    plus = mean + sdev
    minus = mean - sdev
    return plus,minus

## Functions that return a gnuplot function string for a given distribution
def gamma(k,theta, N,fname):
  # gnuplot string for gamma PDF
  # g(x,k,B) = (x**(k - 1) * B**k * exp(-B*x))/gamma(k)
  B = 1.0/theta
   
  ps = fname + '(x) = '+str(N)+'*((x**' + str(k-1) + ')*(' +str(B**k)+ ')*(exp(-' + str(B) +'*x)))' +'/gamma('+str(k)+')\n'
  return ps

def pareto(k,Xm,N,fname):
  # gnuplot string for shifted, normalized exponential PDF
  # g(x,k,B) = (N * k*(Xm**k)/x**(k+1)))
  ps = fname+'(x)=(x<='+str(Xm)+') ? 0 : (('+str((N*k)*(Xm**k))+')/((x)**('+str(k+1)+')))\n'
  #ps = fname+'(x)='+str(N*k*(Xm**k))+'/x**('+str(k+1)+')\n'
  return ps

def pypareto(x, k,Xm):
  # gnuplot string for shifted, normalized exponential PDF
  # g(x,k,B) = (N * k*(Xm**k)/x**(k+1)))
  if x<Xm: return 0
  else: return ((((k)*(Xm**k)))/((x)**((k+1))))

def exp(mean,shift,N,fname):
  # gnuplot string for normalized exponential PDF
  # g(x,k,B) = N * l*exp(-l*(x-shift))
  l = 1.0/mean
  ps = fname+'(x)=(x<'+str(shift)+')?0:('+str(N*l)+'*exp(-abs('+str(l)+'*(x-'+str(shift)+'))))\n'
  return ps

def shiftedExp(mean,shift,N,fname):
  # gnuplot string for shifted, normalized exponential PDF
  # g(x,k,B) = N * l*exp(-l*(x-shift))/(1+(1-exp(-l*shift)))
  l = 1.0/mean
  ps = fname+'(x)='+str(N*l)+'*exp(-abs('+str(l)+'*(x-'+str(shift)+')))/(1+(1-exp(-'+str(l*shift)+')))\n'
  return ps

def poisson(u,N,fname):
  ps = fname + "(x) = " + str(N) + "*(" + str(u) + "**x)*exp(-"+str(u)+")/gamma(x + 1)\n"
  return ps

def normal(u,d,N,fname):
  ps = fname + "(x)="+str(int(N)/d)+"*(exp(-((x-"+str(u)+ ")**2)/"+str(2*d*d)+"))/sqrt(2*pi)\n"
  return ps


def usage():
  print "usage: shufflebt.py [-n <number of circuits>] [-s] [-g] [-k <k value>] [-d outdirname] [-r <res in ms>] <list of filenames>"
  sys.exit(1)

def intermediate_filename(infile,shuffle,truncate,outdir):

  if not shuffle and not truncate: return os.path.abspath(infile)

  intermediate = [os.path.join(os.path.abspath(outdir),os.path.basename(infile))]
  if truncate: intermediate.append(str(truncate))
  if shuffle:
    intermediate.append('shuffled')
  return '.'.join(intermediate)

def histogram_basefilename(infile,shuffle,truncate,res,outdir):
  name = [os.path.join(os.path.abspath(outdir),os.path.basename(infile))]

  if truncate: name.append(str(truncate))
  if shuffle: name.append('shuffled')
  name.append('res' + str(res))
  return '.'.join(name)
    
def getargs():
  # [-n <truncate to # circuits>] [-s] <list of filenames>
  k = 3
  res = 100 
  sort =False
  truncate = None
  graph = False
  outdirname = "." # will write to current directory if not specified
  filenames = []
  if len(sys.argv) < 2: usage()
  else:
    arglen = len(sys.argv[1:])
    i = 0
    while (arglen - i) > 0:
      if sys.argv[i+1] == '-s': sort = True
      elif sys.argv[i+1] == '-n': 
        if not sys.argv[i + 2].isdigit(): usage()
        truncate = sys.argv[i+2]
        i += 1
      elif sys.argv[i + 1] == '-g': graph = True
      elif sys.argv[i + 1] == '-k': 
        k = float(sys.argv[i + 2])
        i += 1
      elif sys.argv[i+1] == '-d': 
        outdirname = sys.argv[i + 2]
        i += 1
      elif sys.argv[i+1] == '-r':
        res = float(sys.argv[i+2])
        i += 1
      else:
        filenames += [sys.argv[i+1]]
      i += 1


  return sort, truncate,graph,outdirname,filenames,k,res
        

def shuffle(sort,truncate,filename,newfile):
  if not sort and truncate is None: return
  sortlocation = '/usr/local/bin/sort'  #peculiarity of fallon's system
  #sortlocation = 'sort'
  if sort and truncate:
    cmd =  sortlocation + ' -R ' + filename + ' | head -n ' + truncate  + ' > ' + newfile
  elif sort and not truncate:
    cmd = sortlocation + ' -R ' + filename + ' > ' + newfile
  elif not sort and truncate:
    cmd = 'cat ' +  filename + ' | head -n ' + truncate  + ' > ' + newfile
    
  p = popen2.Popen4(cmd)
  p.wait()

if __name__ == "__main__":
  sort, truncate,graph,dirname,filenames,k,res = getargs()

  # make new directory
  print 'Making new directory:',dirname
  if not os.path.isdir(dirname):
    os.mkdir(dirname)
  else:
    print 'Dir exists, not making a new one'

  for filename in filenames:
    if os.path.isdir(filename):
      # shallow add of files in dir
      for f in os.listdir(filename):
        if f[-11:] == '.buildtimes':
          filenames += [os.path.join(filename,f)]
      filenames.remove(filename)

  for filename in filenames:
    print 'Processing',filename
    print '------------------------------'
    if not os.path.exists(filename):
      print filename,'is not a valid path'
      continue
#    if truncate and sort or truncate and not sort:
#      newfile = os.path.join(dirname, os.path.basename(filename) + '.' + truncate + '.shuffled')
#    elif sort and not truncate:
#      newfile = os.path.join(dirname , os.path.basename(filename) + '.shuffled')
#    else:
#      newfile =  filename 
    newfile = intermediate_filename(filename,sort,truncate,dirname)
    # shuffle, create new file
    shuffle(sort,truncate,filename,newfile)
 
    # create histogram from file
    s = Stats(newfile)
    histfilename = histogram_basefilename(filename,sort,truncate,res,dirname)
    s.makehistogram(res,histfilename + '.hist')
    mean = s.mean()
    stddev = s.stddev()
    median = s.median()
    mode = s.mode() # relies on s.makehistogram for buckets

    # XXX: Try EZfit and/or frechet function
    parK = s.paretoK(mode)
    modeN = s.modeN(mode)
    modeMean = s.modeMean(mode)
    # verify sanity by integrating scaled distribution:
    modeNint = trapz(map(lambda x: modeN* pypareto(x, parK, mode),
                     xrange(1,200000)))

    print 'Resolution of histogram:',res,'ms'
    print 'Mean: '+str(mean)+', mode: '+str(mode)
    print 'ParK: '+str(parK)
    print 'ModeN: '+str(modeN)+" vs integrated: "+str(modeNint)
    print '#successful runs:',len(s.values)
    # get stats
   
    if graph:
      # plot histogram
      # args: values, # bins, normalize y/n, width of bars
      pylab.hist(s.values,(max(s.values)-min(s.values))/res, 
                 normed=True,width=5)

      #plot Pareto curve
      X = pylab.arange(mode, max(s.values), 1)
      Y = map(lambda x: pypareto(x, parK, mode), X) 
      n = len(s.values)


      pylab.plot(X,Y,'b-')

      #save figure
      pylab.savefig(histfilename + '.png')
      pylab.clf()


