#!/usr/bin/python
#
# Uses the binomial distribution to estimate the expected number of
# circuit 15-circ groups before a false positive that discards all of our
# 15-circ groups for a few different parameters.


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

twenty_pct = BinomialF(.2, 15, 12)
thirty_pct = BinomialF(.3, 15, 12)
fourty_pct = BinomialF(.4, 15, 12)
fifty_pct = BinomialF(.5, 15, 12)
sixty_pct = BinomialF(.6, 15, 12)
seventy_pct = BinomialF(.7, 15, 12)
eighty_pct = BinomialF(.8, 15, 12)
ninety_pct = BinomialF(.9, 15, 12)

print "12 out of 15:"
print "20% circ timeout rate expects "+str(1.0/twenty_pct)+" 15-circ groups"
print "30% circ timeout rate expects "+str(1.0/thirty_pct) +" 15-circ groups"
print "40% circ timeout rate expects "+str(1.0/fourty_pct) +" 15-circ groups"
print "50% circ timeout rate expects "+str(1.0/fifty_pct)+" 15-circ groups"
print "60% circ timeout rate expects "+str(1.0/sixty_pct)+" 15-circ groups"
print "70% circ timeout rate expects "+str(1.0/seventy_pct)+" 15-circ groups"
print "80% circ timeout rate expects "+str(1.0/eighty_pct)+" 20-circ groups"
print "90% circ timeout rate expects "+str(1.0/ninety_pct)+" 20-circ groups"
print

twenty_pct = BinomialF(.2, 15, 13)
thirty_pct = BinomialF(.3, 15, 13)
fourty_pct = BinomialF(.4, 15, 13)
fifty_pct = BinomialF(.5, 15, 13)
sixty_pct = BinomialF(.6, 15, 13)
seventy_pct = BinomialF(.7, 15, 13)
eighty_pct = BinomialF(.8, 15, 13)
ninety_pct = BinomialF(.9, 15, 13)

print "13 out of 15:"
print "20% circ timeout rate expects "+str(1.0/twenty_pct) +" 15-circ groups"
print "30% circ timeout rate expects "+str(1.0/thirty_pct) +" 15-circ groups"
print "40% circ timeout rate expects "+str(1.0/fourty_pct) +" 15-circ groups"
print "50% circ timeout rate expects "+str(1.0/fifty_pct)+" 15-circ groups"
print "60% circ timeout rate expects "+str(1.0/sixty_pct)+" 15-circ groups"
print "70% circ timeout rate expects "+str(1.0/seventy_pct)+" 15-circ groups"
print "80% circ timeout rate expects "+str(1.0/eighty_pct)+" 20-circ groups"
print "90% circ timeout rate expects "+str(1.0/ninety_pct)+" 20-circ groups"
print

twenty_pct = BinomialF(.2, 15, 14)
thirty_pct = BinomialF(.3, 15, 14)
fourty_pct = BinomialF(.4, 15, 14)
fifty_pct = BinomialF(.5, 15, 14)
sixty_pct = BinomialF(.6, 15, 14)
seventy_pct = BinomialF(.7, 15, 14)
eighty_pct = BinomialF(.8, 15, 14)
ninety_pct = BinomialF(.9, 15, 14)

print "14 out of 15:"
print "20% circ timeout rate expects "+str(1.0/twenty_pct)+" 15-circ groups"
print "30% circ timeout rate expects "+str(1.0/thirty_pct) +" 15-circ groups"
print "40% circ timeout rate expects "+str(1.0/fourty_pct) +" 15-circ groups"
print "50% circ timeout rate expects "+str(1.0/fifty_pct)+" 15-circ groups"
print "60% circ timeout rate expects "+str(1.0/sixty_pct)+" 15-circ groups"
print "70% circ timeout rate expects "+str(1.0/seventy_pct)+" 15-circ groups"
print "80% circ timeout rate expects "+str(1.0/eighty_pct)+" 20-circ groups"
print "90% circ timeout rate expects "+str(1.0/ninety_pct)+" 20-circ groups"
print
