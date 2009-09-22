#!/usr/bin/python
#
# Uses the binomial distribution to estimate the expected number of
# circuit trials before a false positive that discards all of our
# circuits for a few different parameters.


import math

def fact(n):
  if n==1: return 1
  return n*fact(n-1)

def choose(n, k): return fact(n)/(fact(k)*fact(n-k))
def binomial(p, n, k): return choose(n,k)*math.pow(p,k)*math.pow(1-p,n-k)

def BinomialF(p, n, k):
  F = 0.0
  for i in xrange(k,n): F+=binomial(p,n,i)
  return F

twenty_pct = BinomialF(.2, 20, 15)
fifty_pct = BinomialF(.5, 20, 15)

print "15 out of 20:"
print "20% circ timeout rate expects: "+str(1.0/twenty_pct)+" trials"
print "50% circ timeout rate expects: "+str(1.0/fifty_pct)+" trials"
print

twenty_pct = BinomialF(.2, 20, 16)
fifty_pct = BinomialF(.5, 20, 16)

print "16 out of 20:"
print "20% circ timeout rate expects: "+str(1.0/twenty_pct) +" trials"
print "50% circ timeout rate expects: "+str(1.0/fifty_pct)+" trials"
print

twenty_pct = BinomialF(.2, 20, 18)
fifty_pct = BinomialF(.5, 20, 18)

print "18 out of 20:"
print "20% circ timeout rate expects: "+str(1.0/twenty_pct)+" trials"
print "50% circ timeout rate expects: "+str(1.0/fifty_pct)+" trials"
print
