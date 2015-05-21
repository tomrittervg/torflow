#!/usr/bin/env python

import sys

def ns_update(alpha, bw, r):
  return bw*((1.0-alpha)+alpha*r)

def main():
  alpha = float(sys.argv[1])
  bw = bw_orig = 1024
  r = 2.5
  for i in xrange(30):
    print bw
    bw = ns_update(alpha, bw, r)
    if r < 1 and bw < bw_orig*r:
      print i
      break

main()
