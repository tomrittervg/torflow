#!/usr/bin/python
#
# Uses the binomial distribution to estimate the expected number of
# circuit 10-circ groups before a false positive that discards all of our
# 10-circ groups for a few different parameters.


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

twenty_pct = BinomialF(.2, 10, 7)
thirty_pct = BinomialF(.35, 10, 7)
fourty_pct = BinomialF(.4, 10, 7)
fifty_pct = BinomialF(.5, 10, 7)
sixty_pct = BinomialF(.6, 10, 7)
seventy_pct = BinomialF(.7, 10, 7)
eighty_pct = BinomialF(.8, 10, 7)
ninety_pct = BinomialF(.9, 10, 7)

print "7 out of 10:"
print "20% circ timeout rate expects "+str(1.0/twenty_pct)+" 10-circ groups"
print "30% circ timeout rate expects "+str(1.0/thirty_pct) +" 10-circ groups"
print "40% circ timeout rate expects "+str(1.0/fourty_pct) +" 10-circ groups"
print "50% circ timeout rate expects "+str(1.0/fifty_pct)+" 10-circ groups"
print "60% circ timeout rate expects "+str(1.0/sixty_pct)+" 10-circ groups"
print "70% circ timeout rate expects "+str(1.0/seventy_pct)+" 10-circ groups"
print "80% circ timeout rate expects "+str(1.0/eighty_pct)+" 20-circ groups"
print "90% circ timeout rate expects "+str(1.0/ninety_pct)+" 20-circ groups"
print

twenty_pct = BinomialF(.2, 10, 8)
thirty_pct = BinomialF(.3, 10, 8)
fourty_pct = BinomialF(.4, 10, 8)
fifty_pct = BinomialF(.5, 10, 8)
sixty_pct = BinomialF(.6, 10, 8)
seventy_pct = BinomialF(.7, 10, 8)
eighty_pct = BinomialF(.8, 10, 8)
ninety_pct = BinomialF(.9, 10, 8)

print "8 out of 10:"
print "20% circ timeout rate expects "+str(1.0/twenty_pct) +" 10-circ groups"
print "30% circ timeout rate expects "+str(1.0/thirty_pct) +" 10-circ groups"
print "40% circ timeout rate expects "+str(1.0/fourty_pct) +" 10-circ groups"
print "50% circ timeout rate expects "+str(1.0/fifty_pct)+" 10-circ groups"
print "60% circ timeout rate expects "+str(1.0/sixty_pct)+" 10-circ groups"
print "70% circ timeout rate expects "+str(1.0/seventy_pct)+" 10-circ groups"
print "80% circ timeout rate expects "+str(1.0/eighty_pct)+" 20-circ groups"
print "90% circ timeout rate expects "+str(1.0/ninety_pct)+" 20-circ groups"
print

twenty_pct = BinomialF(.2, 10, 9)
thirty_pct = BinomialF(.30, 10, 9)
fourty_pct = BinomialF(.40, 10, 9)
fifty_pct = BinomialF(.5, 10, 9)
sixty_pct = BinomialF(.6, 10, 9)
seventy_pct = BinomialF(.7, 10, 9)
eighty_pct = BinomialF(.8, 10, 9)
ninety_pct = BinomialF(.9, 10, 9)

print "9 out of 10:"
print "20% circ timeout rate expects "+str(1.0/twenty_pct)+" 10-circ groups"
print "30% circ timeout rate expects "+str(1.0/thirty_pct) +" 10-circ groups"
print "40% circ timeout rate expects "+str(1.0/fourty_pct) +" 10-circ groups"
print "50% circ timeout rate expects "+str(1.0/fifty_pct)+" 10-circ groups"
print "60% circ timeout rate expects "+str(1.0/sixty_pct)+" 10-circ groups"
print "70% circ timeout rate expects "+str(1.0/seventy_pct)+" 10-circ groups"
print "80% circ timeout rate expects "+str(1.0/eighty_pct)+" 20-circ groups"
print "90% circ timeout rate expects "+str(1.0/ninety_pct)+" 20-circ groups"
print
