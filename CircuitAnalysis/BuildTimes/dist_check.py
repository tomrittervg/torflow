#!/usr/bin/env python
# Checks the distribution of circuits 

try:
  import psyco
  psyco.full()
except ImportError:
  #print 'Psyco not installed, the program will just run slower'
  pass

#import profile

import socket,sys,time,getopt,os,threading
sys.path.append("../../")
import TorCtl
from TorCtl.TorUtil import meta_port,meta_host,control_port,control_host,control_pass
from TorCtl.StatsSupport import StatsHandler
from TorCtl import PathSupport, TorCtl
from TorCtl.PathSupport import ExitPolicyRestriction,OrNodeRestriction
from TorCtl.TorUtil import plog

def usage():
  print "Option fail."

def getargs():
  if len(sys.argv[1:]) < 2:
    usage()
    sys.exit(2)

  pathfile=None
  try:
    opts,args = getopt.getopt(sys.argv[1:],"f:")
  except getopt.GetoptError,err:
    print str(err)
    usage()
  for o,a in opts:
    if o == '-f': 
      pathfile = a
    else:
      assert False, "Bad option"
  return pathfile

def open_controller():
  """ starts stat gathering thread """

  s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect((control_host,control_port))
  c = PathSupport.Connection(s)
  c.authenticate(control_pass)  # also launches thread...


  return c


class ChosenRouter(TorCtl.Router):
  def __init__(self, router):
    self.__dict__ = router.__dict__
    self.chosen = [0,0,0]


def main():
  pathfile = getargs()
  c=open_controller()  

  routers = map(ChosenRouter, c.read_routers(c.get_network_status())) 
  router_map = {}
  for r in routers:
    router_map[r.idhex] = r

  routers.sort(lambda x, y: cmp(y.bw, x.bw))
  for i in xrange(len(routers)): routers[i].list_rank = i

  f = open(pathfile, "r")

  pct_mins = [100, 100, 100]
  pct_maxes = [0, 0, 0]
  flags = [{},{},{}]
  present={}
  absent={}
  circuits=0

  exit_check = OrNodeRestriction([
                  ExitPolicyRestriction("255.255.255.255", 80),
                  ExitPolicyRestriction("255.255.255.255", 443)])
  
  for line in f:
    nodes = map(lambda n: n.strip(), line.split("\t"))
    id,nodes = (nodes[0],nodes[1:])
    circuits+=1
    for i in xrange(0, len(nodes)):
      if nodes[i] not in router_map:
        #print nodes[i] + " no longer present in map"
        absent[nodes[i]] = 1
        continue
      present[nodes[i]] = 1
      router_map[nodes[i]].chosen[i] += 1
      pct = 100.0*router_map[nodes[i]].list_rank/len(routers)
      if pct < pct_mins[i]:
        pct_mins[i] = pct
      if pct > pct_maxes[i]:
        pct_maxes[i] = pct
      def flag_ctr(f):
        if not f in flags[i]: flags[i][f] = 0
        flags[i][f] += 1
      map(flag_ctr, router_map[nodes[i]].flags)

    if nodes[2] in router_map:
      if not exit_check.r_is_ok(router_map[nodes[2]]):
        print "WARN: Exit policy fail for circ "+str(id)+" on "+nodes[2]
        print "Exit policy:"
        for e in router_map[nodes[2]].exitpolicy:
          print " "+str(e)

    
  # FIXME: Compare circuits/chosen to %bw. Multiply by pct_min+max
  # FIXME: Verify by guard+exit weighting?
  for i in xrange(0, 3):
    routers.sort(lambda x, y: cmp(y.chosen[i], x.chosen[i]))
    print "\nHop "+str(i)+": "
    unchosen = 0
    for r in routers:
      if r.chosen[i] == 0: unchosen+=1
      else: print r.idhex+" chosen: "+str(r.chosen[i]) 

    print "Nodes not chosen for this hop: "+str(unchosen)+"/"+str(len(routers))

    flgs = flags[i].keys()
    flgs.sort(lambda x, y: cmp(y,x))
    for f in flgs:
      if flags[i][f] == circuits:
        print f+": "+str(flags[i][f])+" (all)"
      else:
        print f+": "+str(flags[i][f])


  print "Routers used that are still present: "+str(len(present.keys()))
  print "Routers used that are now absent: "+str(len(absent.keys()))
  print "Min percentiles per hop: "+str(pct_mins)
  print "Max percentiles per hop: "+str(pct_maxes)

if __name__ == '__main__':
  main()

