#!/usr/bin/python
#
# Uses the binomial distribution to estimate the expected number of
# circuit 20-circ groups before a false positive that discards all of our
# 20-circ groups for a few different parameters.


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

twenty_pct = BinomialF(.2, 20, 16)
thirty_pct = BinomialF(.3, 20, 16)
fourty_pct = BinomialF(.4, 20, 16)
fifty_pct = BinomialF(.5, 20, 16)
sixty_pct = BinomialF(.6, 20, 16)
seventy_pct = BinomialF(.7, 20, 16)
eighty_pct = BinomialF(.8, 20, 16)
ninety_pct = BinomialF(.9, 20, 16)

print "16 out of 20:"
print "20% circ timeout rate expects "+str(1.0/twenty_pct)+" 20-circ groups"
print "30% circ timeout rate expects "+str(1.0/thirty_pct) +" 20-circ groups"
print "40% circ timeout rate expects "+str(1.0/fourty_pct) +" 20-circ groups"
print "50% circ timeout rate expects "+str(1.0/fifty_pct)+" 20-circ groups"
print "60% circ timeout rate expects "+str(1.0/sixty_pct)+" 20-circ groups"
print "70% circ timeout rate expects "+str(1.0/seventy_pct)+" 20-circ groups"
print "80% circ timeout rate expects "+str(1.0/eighty_pct)+" 20-circ groups"
print "90% circ timeout rate expects "+str(1.0/ninety_pct)+" 20-circ groups"
print

twenty_pct = BinomialF(.2, 20, 17)
thirty_pct = BinomialF(.3, 20, 17)
fourty_pct = BinomialF(.4, 20, 17)
fifty_pct = BinomialF(.5, 20, 17)
sixty_pct = BinomialF(.6, 20, 17)
seventy_pct = BinomialF(.7, 20, 17)
eighty_pct = BinomialF(.8, 20, 17)
ninety_pct = BinomialF(.9, 20, 17)

print "17 out of 20:"
print "20% circ timeout rate expects "+str(1.0/twenty_pct) +" 20-circ groups"
print "30% circ timeout rate expects "+str(1.0/thirty_pct) +" 20-circ groups"
print "40% circ timeout rate expects "+str(1.0/fourty_pct) +" 20-circ groups"
print "50% circ timeout rate expects "+str(1.0/fifty_pct)+" 20-circ groups"
print "60% circ timeout rate expects "+str(1.0/sixty_pct)+" 20-circ groups"
print "70% circ timeout rate expects "+str(1.0/seventy_pct)+" 20-circ groups"
print "80% circ timeout rate expects "+str(1.0/eighty_pct)+" 20-circ groups"
print "90% circ timeout rate expects "+str(1.0/ninety_pct)+" 20-circ groups"
print

twenty_pct = BinomialF(.2, 20, 18)
thirty_pct = BinomialF(.3, 20, 18)
fourty_pct = BinomialF(.4, 20, 18)
fifty_pct = BinomialF(.5, 20, 18)
sixty_pct = BinomialF(.6, 20, 18)
seventy_pct = BinomialF(.7, 20, 18)
eighty_pct = BinomialF(.8, 20, 18)
ninety_pct = BinomialF(.9, 20, 18)

print "18 out of 20:"
print "20% circ timeout rate expects "+str(1.0/twenty_pct)+" 20-circ groups"
print "30% circ timeout rate expects "+str(1.0/thirty_pct) +" 20-circ groups"
print "40% circ timeout rate expects "+str(1.0/fourty_pct) +" 20-circ groups"
print "50% circ timeout rate expects "+str(1.0/fifty_pct)+" 20-circ groups"
print "60% circ timeout rate expects "+str(1.0/sixty_pct)+" 20-circ groups"
print "70% circ timeout rate expects "+str(1.0/seventy_pct)+" 20-circ groups"
print "80% circ timeout rate expects "+str(1.0/eighty_pct)+" 20-circ groups"
print "90% circ timeout rate expects "+str(1.0/ninety_pct)+" 20-circ groups"
print
