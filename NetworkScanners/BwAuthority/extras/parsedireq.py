#!/usr/bin/python

# <armadev> mikeperry: v3 fetchers fetch about 8 times a day
# <armadev> v2 fetchers fetch about 48 times a day
# <armadev> except, as karsten pointed out, the v2 fetchers might fetch
#           more than that, since some fail and they retry
# So v2 fetches are 6.0 times more frequent than v3 fetches.

# written 
# n-ns-reqs
# n-v2-ns-reqs

# n-ns-ip
# n-v2-ip

import time
import sys

def total_countries(l):
  reqs = 0
  l = l.split(" ")
  if len(l) != 2:
   print l
   sys.exit(1)
  l = l[1].split(",")
  for c in l:
    c = c.split("=")
    reqs += int(c[1])
  return reqs

f = open("trusted-dirreq", "r")

# t0 from the dirreq dataset:
t0 = time.mktime(time.strptime("2007-03-05", "%Y-%m-%d"))

upgrade_ip_table = {}
upgrade_req_table = {}

l = f.readline()
while l:
  l = l.split(" ")
  if l[0] == "written":
    written = time.mktime(time.strptime(l[1], "%Y-%m-%d"))
    nsreqs = 0
    v2reqs = 0
    nsips = 0
    v2ips = 0
    l = f.readline()
    while l and not l.startswith("ns-ips"): l = f.readline()
    nsreqs = total_countries(l)
    l = f.readline()
    while l and not l.startswith("ns-v2-ips"): l = f.readline()
    v2reqs = total_countries(l)
    l = f.readline()
    while l and not l.startswith("n-ns-reqs"): l = f.readline()
    nsips = total_countries(l)
    l = f.readline()
    while l and not l.startswith("n-v2-ns-reqs"): l = f.readline()
    v2ips = total_countries(l)

    #print "Written at "+time.ctime(written)+" v3-ip: "+str(nsips)+\
    #      " v2-ip: "+str(v2ips)+" v3-reqs: "+str(nsreqs)+\
    #      " v2-reqs "+str(v2reqs)
    upgrade_ip_table[written-t0] = nsips/(nsips+(v2ips/8.0))
    upgrade_req_table[written-t0] = nsreqs/(nsreqs+(v2reqs/8.0))

  l = f.readline()


import logistic

(u_ip, s_ip) = logistic.estimate(upgrade_ip_table)
(u_req, s_req) = logistic.estimate(upgrade_req_table)

print "s_ip="+str(s_ip)+", u_ip="+str(u_ip)
print "Estimate 50% IP upgrade at: "+time.ctime(t0+u_ip)

print "s_req="+str(s_req)+", u_req="+str(u_req)
print "Estimate 50% REQ upgrade at: "+time.ctime(t0+u_req)
