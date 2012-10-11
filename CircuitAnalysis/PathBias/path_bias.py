#!/usr/bin/python

import random

# TODO:
# Q: What quantity of middle bandwidth do you need to kill guards?
# A: Intuitively, you need the disable rate % of bandwidth, but you
# might have some edge cases to exploit with min_circs.

PATH_BIAS_PCT = 70

# XXX: Min_circs only actives the "notice" level logs
PATH_BIAS_MIN_CIRCS = 20

# XXX: An int divisor was wrong here. Fix that in Tor. We might
# even want a weighted moving average, but that will be trickier
# to analyze.
PATH_BIAS_SCALE_FACTOR = 50
PATH_BIAS_SCALE_THRESHOLD = 250

# XXX: We should only emit warnings if we are above the scaling threshhold..
PATH_BIAS_WARN_CIRCS = PATH_BIAS_SCALE_THRESHOLD*(PATH_BIAS_SCALE_FACTOR/100.0)

#############################################################

# FIXME: haxxx. Who cares, though?
def reset_globals():
  global PATH_BIAS_PCT
  global PATH_BIAS_MIN_CIRCS
  global PATH_BIAS_SCALE_FACTOR
  global PATH_BIAS_SCALE_THRESHOLD
  global PATH_BIAS_WARN_CIRCS

  PATH_BIAS_PCT = 70
  PATH_BIAS_MIN_CIRCS = 20
  PATH_BIAS_SCALE_FACTOR = 50
  PATH_BIAS_SCALE_THRESHOLD = 250
  PATH_BIAS_WARN_CIRCS = PATH_BIAS_SCALE_THRESHOLD*(PATH_BIAS_SCALE_FACTOR/100.0)


####################### Guard Types #########################

# Normal Guard experiences the average circuit failure rate
# of the network as a whole
class Guard:
  def __init__(self, succeed_rate):
    self.first_hops_total = 0
    self.success_total = 0

    self._first_hops = 0
    self._success = 0
    self.succeed_rate = succeed_rate
    self.rejected_count = 0

  def reset(self):
    self._success = 0
    self._first_hops = 0

  def reject_if_bad(self):
    if self.is_bad():
      self.reset()
      self.rejected_count += 1

  def reject_rate(self):
    return self.rejected_count/float(self.first_hops_total)

  def _get_rate(self):
    return self._success/float(self._first_hops)

  def is_bad(self):
    return self._first_hops >= PATH_BIAS_MIN_CIRCS and \
           (self._get_rate() < (PATH_BIAS_PCT/100.0))

  def build_circuit(self):
   self._inc_first_hop()
   if random.random() < self.succeed_rate:
      self._inc_success()

   # Client may give up on us after this circuit
   self.reject_if_bad()

  def circ_fail_count(self):
    return self._first_hops - self._success

  def _inc_first_hop(self):
    self._first_hops += 1
    self.first_hops_total += 1
    if self._first_hops > PATH_BIAS_SCALE_THRESHOLD:
      self._first_hops *= PATH_BIAS_SCALE_FACTOR/100.0
      self._success *= PATH_BIAS_SCALE_FACTOR/100.0

  def _inc_success(self):
    self._success += 1
    self.success_total += 1

# EvilGuard collects statistics on how evil he is, but doesn't
# actually implement any evilness
class EvilGuard(Guard):
  def __init__(self, succeed_rate, adversary_capacity):
    Guard.__init__(self, succeed_rate)
    self.adversary_capacity = adversary_capacity # c/n probability of malicious exit
    self.capture_count = 0

  def pwnt_per_client(self):
    return self.capture_count/float(self.rejected_count+1)

  def capture_rate(self):
    return self.capture_count/float(self.first_hops_total)

  def compromise_rate(self):
    return self.capture_count/float(self.success_total)

# PassiveEvilGuard uses a non-destructive long-term timing-based
# tagging attack to fully correlate circuits end-to-end with 100%
# accuracy. PassiveEvilGuard does not kill any circuits.
class PassiveEvilGuard(EvilGuard):
  def __init__(self, succeed_rate, adversary_capacity):
    EvilGuard.__init__(self, succeed_rate, adversary_capacity)

  def build_circuit(self):
    self._inc_first_hop()

    # The presence of a malicious exit is a prior probability governed by the
    # client. Decide it now.
    got_malicious_exit = False
    if random.random() < self.adversary_capacity:
      got_malicious_exit = True

    if random.random() < self.succeed_rate:
      if got_malicious_exit: # via timing-based tagging attack
        self._inc_success()
        self.capture_count += 1
      else:
        self._inc_success() # "Better luck next time :/"

    # Client may give up on us after this circuit
    self.reject_if_bad()

# UnrepentantEvilGuard uses a destructive tagging attack to
# fully correlate circuits end-to-end with 100%
# accuracy, as well as to kill uncorrelated circuits.
#
# UnrepentantEvilGuard doesn't care if there is a defense or
# not.
class UnrepentantEvilGuard(EvilGuard):
  def __init__(self, succeed_rate, adversary_capacity):
    EvilGuard.__init__(self, succeed_rate, adversary_capacity)

  def build_circuit(self):
    self._inc_first_hop()

    # The presence of a malicious exit is a prior probability governed by the
    # client. Decide it now.
    got_malicious_exit = False
    if random.random() < self.adversary_capacity:
      got_malicious_exit = True

    if random.random() < self.succeed_rate:
      if got_malicious_exit: # via tagging attack
        self._inc_success()
        self.capture_count += 1
      else:
        pass # "We can't deanon it? Who cares then?"

    # Client may give up on us after this circuit
    self.reject_if_bad()

# OmniscientEvilGuard is the worst-case adversary against
# the path bias counters implemented in Tor 0.2.3.17.
#
# OmniscientEvilGuard knows client path counts, when they are about to
# think it's bad, and when they scale, and tries to use all of these
# to fail what it can to bias client paths without appearing bad to
# them.
#
# Further in favor of the adversary, we assume that their circuit
# failure rate is actually less than the network average by
# the fraction of the network that they control (because the rest
# of the network experiences this circuit failure as part of the
# average failure).
#
# Further still, OmnscientEvilGuard is *so* omnsicient, it even knows
# when circuits will fail due to ambient noise, so it never gets
# killed by chance. (It is debatable how much this helps.. a
# smart adversary could play the stats close enough to the line
# to approach this omniscience asymptotically).
#
# Note: These omniscience assumptions all favor the attacker,
# but they also simplify analysis to get worst-case bounds easily.
#
# XXX: Introducing some fuzz into our scaling count and/or rate might
# help remove this exact omniscience in practice?
class OmniscientEvilGuard(EvilGuard):
  def __init__(self, succeed_rate, adversary_capacity):
    EvilGuard.__init__(self, succeed_rate, adversary_capacity)

  def look_ahead(self, n):
    self.prev_first_hops = self._first_hops
    self.prev_success = self._success
    self.prev_first_hops_total = self.first_hops_total
    self.prev_success_total = self.success_total
    for i in xrange(n):
      self._inc_first_hop()

  def stop_looking(self):
    self._first_hops = self.prev_first_hops
    self._success = self.prev_success
    self.first_hops_total = self.prev_first_hops_total
    self.success_total = self.prev_success_total

  # This guard should never get caught
  def reject_if_bad(self):
    assert not self.is_bad()

  def build_circuit(self):
    self._inc_first_hop()

    # The presence of a malicious exit is a prior probability governed by the
    # client. Decide it now.
    got_malicious_exit = False
    if random.random() < self.adversary_capacity:
      got_malicious_exit = True

    # In reality, OmniscientEvilGuard sees less failure because some
    # of the failure in the network is due to other colluding nodes.
    #if random.random() < self.succeed_rate + self.adversary_capacity:
    #
    # Note: We cut this out, because it favors the attacker to do so.
    # It removes the risk of elimination by chance (which they could mitigate
    # for an unknown but possibly small cost).
    if True:
      if got_malicious_exit: # via tagging attack
        self.capture_count += 1
        self._inc_success() # "We built a circuit! Yay!"
      else:
        # Look-ahead only needs to be non-zero to mitigate risk of random rejection
        self.look_ahead(0)
        if (self._get_rate() <= (PATH_BIAS_PCT/100.0)):
          self.stop_looking()
          self._inc_success() # "I better be good! don't want to get caught.."
        else:
          pass # Fail the circuit by doing nothing. It's not useful

    # Client may give up on us after this circuit
    self.reject_if_bad()

# ProbabalisticEvilGuard only fails untagged circuits pct_below_path_bias
# below the warning rate
class ProbabalisticEvilGuard(EvilGuard):
  def __init__(self, succeed_rate, adversary_capacity, pct_below_path_bias):
    EvilGuard.__init__(self, succeed_rate, adversary_capacity)
    # FIXME: There may be an optimal point where pct_below_path_bias
    # is the lowest possible value that the adversary expects to control?
    # Doesn't seem to be worth probing, though
    self.path_bias_rate = (PATH_BIAS_PCT - pct_below_path_bias)/100.0
    assert self.path_bias_rate <= 1.0

  def build_circuit(self):
    self._inc_first_hop()

    # The presence of a malicious exit is a prior probability governed by the
    # client. Decide it now.
    got_malicious_exit = False
    if random.random() < self.adversary_capacity:
      got_malicious_exit = True

    # ProbabalisticGamingGuard sees less failure because some
    # of the failure in the network is due to other colluding nodes.
    if random.random() < self.succeed_rate + self.adversary_capacity:
      if got_malicious_exit: # via tagging attack
        self._inc_success()
        self.capture_count += 1
      elif not self.success_total or \
         self.success_total/float(self.first_hops_total) <= self.path_bias_rate:
        # "Uh oh, we're failing too much, better let some through"
        self._inc_success()
      else:
        pass # Fail the circuit by doing nothing. It's not useful

    # Client may give up on us after this circuit
    self.reject_if_bad()

####################### Testing and Simulation #########################

def simulate_circs_until(g, circ_count, say_when):
  for i in xrange(circ_count):
    g.build_circuit()
    if say_when(g):
      return True

  return say_when(g)

# Variables:
# success_rate
# PATH_BIAS_MIN_CIRCS = 20
# PATH_BIAS_PCT = 70
def startup_false_positive_test(trials, success_rate, min_circs, path_bias_pct):
  # FIXME: Look it's just easier this way, ok? Get off my back already
  global PATH_BIAS_MIN_CIRCS
  global PATH_BIAS_PCT
  PATH_BIAS_MIN_CIRCS = min_circs
  PATH_BIAS_PCT = path_bias_pct

  g = Guard(success_rate)

  for i in xrange(1+trials/min_circs):
    simulate_circs_until(g, PATH_BIAS_SCALE_THRESHOLD, lambda g: False)
    g.reset()

  #print g._get_rate()

  return g.rejected_count

def reject_false_positive_test(trials, success_rate, scale_circs, path_bias_pct):
  # FIXME: Look it's just easier this way, ok? Get off my back already
  global PATH_BIAS_MIN_CIRCS
  global PATH_BIAS_SCALE_THRESHOLD
  global PATH_BIAS_PCT
  PATH_BIAS_SCALE_THRESHOLD = scale_circs
  PATH_BIAS_PCT = path_bias_pct

  g = Guard(success_rate)

  # Ignore startup. We don't reject then.
  simulate_circs_until(g, PATH_BIAS_SCALE_THRESHOLD, lambda g: False)
  g.rejected_count = 0

  simulate_circs_until(g, trials, lambda g: False)

  return g.rejected_count

def generic_rate_test(g, trials, success_rate, adversary_capacity, path_bias_pct, rate_fcn):
  # FIXME: Look it's just easier this way, ok? Get off my back already
  global PATH_BIAS_PCT
  PATH_BIAS_PCT = path_bias_pct

  simulate_circs_until(g, trials, lambda g: False)

  if not isinstance(g, UnrepentantEvilGuard):
    assert not g.is_bad()

  return rate_fcn(g)

def dos_attack_test(success_rate, dos_success_rate, path_bias_pct, scale_thresh):
  global PATH_BIAS_PCT
  global PATH_BIAS_SCALE_THRESHOLD
  PATH_BIAS_PCT = path_bias_pct
  PATH_BIAS_SCALE_THRESHOLD = scale_thresh

  g = Guard(success_rate)

  simulate_circs_until(g, PATH_BIAS_SCALE_THRESHOLD, lambda g: False)
  g.rejected_count = 0

  g.succeed_rate = dos_success_rate

  simulate_circs_until(g, 10000, lambda g: g.rejected_count > 0)

  return g.first_hops_total - PATH_BIAS_SCALE_THRESHOLD


################ Multi-Dementianal Analysis #####################

# If brute force doesn't work, you're not using enough
def brute_force(cmptr, functor, ranges, increment):
  testpoint = map(lambda p: p[0], ranges)
  maxpoint = testpoint
  maxval = functor(*testpoint)

  print "New extrema at "+str(maxpoint)+": "+str(maxval)

  for dementia in xrange(len(ranges)):
    if increment[dementia] > 0:
      cmpr = lambda x, y: x<y
    else:
      cmpr = lambda x, y: x>y

    value = ranges[dementia][0]
    while cmpr(value, ranges[dementia][1]):
      value += increment[dementia]
      testpoint[dementia] = value
      val = functor(*testpoint)
      if cmptr(val, maxval):
        maxval = val
        maxpoint = testpoint
        print "New extrema at "+str(maxpoint)+": "+str(maxval)

  # FIXME: Haxx
  reset_globals()

  return maxpoint


def surface_plot(functor, startpoint, ranges, increment):
  pass

def gradient_descent(functor, startpoint, ranges, increment):
  # Warning, mentat: If brute force doesn't work, you're not using enough
  # It might be wise to try to get a 3d color plot/heatmap/some other
  # visualization before attempting this?
  pass

def main():
  #random.seed(23)

  if True:
    print "==================== P(Compromise|Guard) =========================="

    print "\nPassiveEvilGuard compromise rate at [success_rate, adversary_capacity, path_bias_pct]:"
    print "(As expected, P(CompromisedExit|PassiveEvilGuard) ~= c/n)"
    print brute_force(lambda x,y: x>y,
                      lambda t, a,b,c:
                        generic_rate_test(PassiveEvilGuard(a,b), t, a,b,c,
                                          lambda g:
                                            g.compromise_rate()),
                     #generic_rate_test(trials, success_rate, adversary_capacity, path_bias_pct):
                     [(10000,10000), (0.75,0.75), (0.05,0.85), (70, 70)],
                     [0, 0, 0.2, 5])


    print "\nUnrepentantEvilGuard compromise rate at [success_rate, adversary_capacity, path_bias_pct]:"
    print "(As expected, P(CompromisedExit|UnrepentantEvilGuard) = 1.0)"
    print brute_force(lambda x,y: x>y,
                      lambda t,a,b,c:
                        generic_rate_test(UnrepentantEvilGuard(a,b), t,a,b,c,
                                          lambda g:
                                            g.compromise_rate()),
                     #generic_rate_test(trials, success_rate, adversary_capacity, path_bias_pct):
                     [(10000,10000), (0.75,0.75), (0.05,0.85), (70, 70)],
                     [0, 0, 0.2, 5])

    print "\nProbabalisticEvilGuard compromise rate at [success_rate, adversary_capacity, path_bias_pct]:"
    print "P(CompromisedExit|ProbabalisticEvilGuard) <= (c/n)*(100/PATH_BIAS_PCT)"
    print brute_force(lambda x,y: x>y,
                      lambda t,a,b,c:
                        generic_rate_test(ProbabalisticEvilGuard(a,b,5),
                                          t,a,b,c,
                                          lambda g:
                                            g.compromise_rate()),
                     #generic_rate_test(trials, success_rate, adversary_capacity, path_bias_pct):
                     [(10000,10000), (0.75,0.75), (0.05,0.85), (70, 70)],
                     [0, 0, 0.2, 5])

    print "\nOmniscientEvilGuard compromise rate at [success_rate, adversary_capacity, path_bias_pct]:"
    print "P(CompromisedExit|OmniscientEvilGuard) <= (c/n)*(100/PATH_BIAS_PCT)"
    print brute_force(lambda x,y: x>y,
                      lambda t,a,b,c:
                        generic_rate_test(OmniscientEvilGuard(a,b), t,a,b,c,
                                          lambda g:
                                            g.compromise_rate()),
                     #generic_rate_test(trials, success_rate, adversary_capacity, path_bias_pct):
                     [(10000,10000), (0.75,0.75), (0.05,0.85), (70, 70)],
                     [0, 0, 0.2, 5])

    print "\nOmniscientEvilGuard compromise at [success_rate, adversary_capacity, path_bias_pct]:"
    print "P(CompromisedExit|OmniscientEvilGuard) <= (c/n)*(100/PATH_BIAS_PCT)"
    print brute_force(lambda x,y: x<y,
                      lambda t,a,b,c:
                        generic_rate_test(OmniscientEvilGuard(a,b), t,a,b,c,
                                          lambda g:
                                            g.compromise_rate()),
                     #generic_rate_test(trials, success_rate, adversary_capacity, path_bias_pct):
                     [(10000,10000), (0.75,0.75), (0.20,0.20), (20, 80)],
                     [0, 0, 0.05, 20])

  if True:
    print "\n\n==================== Circuits pwnt per client ========================="

    print "\nUnrepentantEvilGuard compromised circs at [success_rate, adversary_capacity, path_bias_pct]:"
    print "circs_per_client ~= success_rate*c/n*MIN_CIRCS      for c/n < PATH_BIAS_PCT || c/n < success_rate"
    print "                 ~= success_rate*circ_attempts*c/n  for c/n > PATH_BIAS_PCT && c/n > success_rate"
    print brute_force(lambda x,y: x>y,
                      lambda t,a,b,c:
                        generic_rate_test(UnrepentantEvilGuard(a,b), t,a,b,c,
                                          lambda g:
                                            g.pwnt_per_client()),
                     #generic_rate_test(trials, success_rate, adversary_capacity, path_bias_pct):
                     [(100000,100000), (0.75,0.75), (0.05,0.85), (50, 50)],
                     [0, 0, 0.2, 5])

    print "\nPassiveEvilGuard compromised circs at [success_rate, adversary_capacity, path_bias_pct]:"
    print "circs_per_client ~= success_rate * circ_attempts * c/n"
    print brute_force(lambda x,y: x>y,
                      lambda t,a,b,c:
                        generic_rate_test(PassiveEvilGuard(a,b),
                                          t,a,b,c,
                                          lambda g:
                                            g.pwnt_per_client()),
                     #generic_rate_test(trials, success_rate, adversary_capacity, path_bias_pct):
                     [(100000,100000), (0.75,0.75), (0.05,0.85), (50, 50)],
                     [0, 0, 0.2, 5])

    print "\nProbabalisticEvilGuard compromised circs at [success_rate, adversary_capacity, path_bias_pct]:"
    print "circs_per_client ~= success_rate * circ_attempts * c/n"
    print brute_force(lambda x,y: x>y,
                      lambda t,a,b,c:
                        generic_rate_test(ProbabalisticEvilGuard(a,b,5),
                                          t,a,b,c,
                                          lambda g:
                                            g.pwnt_per_client()),
                     #generic_rate_test(trials, success_rate, adversary_capacity, path_bias_pct):
                     [(100000,100000), (0.75,0.75), (0.05,0.85), (50, 50)],
                     [0, 0, 0.2, 5])

    print "\nOmniscientEvilGuard compromised circs at [success_rate, adversary_capacity, path_bias_pct]:"
    print "circs_per_client ~= circ_attempts * c/n"
    print brute_force(lambda x,y: x>y,
                      lambda t,a,b,c:
                        generic_rate_test(OmniscientEvilGuard(a,b), t,a,b,c,
                                          lambda g:
                                            g.pwnt_per_client()),
                     #generic_rate_test(trials, success_rate, adversary_capacity, path_bias_pct):
                     [(100000,100000), (0.75,0.75), (0.05,0.85), (50, 50)],
                     [0, 0, 0.2, 5])


  if True:
    print "\n\n===================== False Positives ============================"

    print "\nStartup false positive counts at [num_circs, success_rate, min_circs, path_bias_pct]:"
    print "(Results are some function of success_rate - path_bias_pct vs min_circs)"
    print brute_force(lambda x,y: x<y,
                     startup_false_positive_test,
                     #false_positive_test(num_circs, success_rate, min_circs, path_bias_pct):
                     [(1000000,1000000), (0.80, 0.80), (25,250), (70, 70)],
                     [0, -0.1, 25, 5])

    print "\nStartup false positive counts at [num_circs, success_rate, min_circs, path_bias_pct]:"
    print "(Results are some function of success_rate - path_bias_pct vs min_circs)"
    print brute_force(lambda x,y: x<y,
                     startup_false_positive_test,
                     #false_positive_test(num_circs, success_rate, min_circs, path_bias_pct):
                     [(1000000,1000000), (0.45, 0.45), (25,250), (30, 30)],
                     [0, -0.1, 25, 5])


    print "\nFalse positive counts at [num_circs, success_rate, scale_circs, path_bias_pct]:"
    print "(Results are some function of success_rate - path_bias_pct vs scale_circs)"
    print brute_force(lambda x,y: x<y,
                     reject_false_positive_test,
                     #false_positive_test(num_circs, success_rate, scale_circs, path_bias_pct):
                     [(1000000,1000000), (0.70, 0.70), (100,500), (70, 70)],
                     [0, -0.1, 50, 5])

    print "\nFalse positive counts at [num_circs, success_rate, scale_circs, path_bias_pct]:"
    print "(Results are some function of success_rate - path_bias_pct vs scale_circs)"
    print brute_force(lambda x,y: x<y,
                     reject_false_positive_test,
                     #false_positive_test(num_circs, success_rate, scale_circs, path_bias_pct):
                     [(1000000,1000000), (0.75, 0.75), (100,500), (70, 70)],
                     [0, -0.1, 50, 5])

    print "\nFalse positive counts at [num_circs, success_rate, scale_circs, path_bias_pct]:"
    print "(Results are some function of success_rate - path_bias_pct vs scale_circs)"
    print brute_force(lambda x,y: x<y,
                     reject_false_positive_test,
                     #false_positive_test(num_circs, success_rate, scale_circs, path_bias_pct):
                     [(1000000,1000000), (0.80, 0.80), (100,500), (70, 70)],
                     [0, -0.1, 50, 5])

    print "\nFalse positive counts at [num_circs, success_rate, scale_circs, path_bias_pct]:"
    print "(Results are some function of success_rate - path_bias_pct vs scale_circs)"
    print brute_force(lambda x,y: x<y,
                     reject_false_positive_test,
                     #false_positive_test(num_circs, success_rate, scale_circs, path_bias_pct):
                     [(1000000,1000000), (0.55, 0.55), (100,500), (50, 50)],
                     [0, -0.1, 50, 5])

    print "\nFalse positive counts at [num_circs, success_rate, scale_circs, path_bias_pct]:"
    print "(Results are some function of success_rate - path_bias_pct vs scale_circs)"
    print brute_force(lambda x,y: x<y,
                     reject_false_positive_test,
                     #false_positive_test(num_circs, success_rate, scale_circs, path_bias_pct):
                     [(1000000,1000000), (0.60, 0.60), (100,500), (50, 50)],
                     [0, -0.1, 50, 5])

    print "\nFalse positive counts at [num_circs, success_rate, scale_circs, path_bias_pct]:"
    print "(Results are some function of success_rate - path_bias_pct vs scale_circs)"
    print brute_force(lambda x,y: x<y,
                     reject_false_positive_test,
                     #false_positive_test(num_circs, success_rate, scale_circs, path_bias_pct):
                     [(1000000,1000000), (0.45, 0.45), (100,500), (30, 30)],
                     [0, -0.1, 50, 5])

  if True:
    print "\n\n===================== DoS Attack Duration ========================"
    print "\nDoS attack durations (in circs) at [success_rate, dos_success_rate, path_bias_pct, scale_thresh]:"
    print brute_force(lambda x,y: x<y,
                     dos_attack_test,
                     #dos_attack_test(g, num_circs, success_rate, dos_success_rate, path_bias_pct):
                     #false_positive_test(num_circs, success_rate, scale_circs, path_bias_pct):
                     [(0.80, 0.80), (0.25,0.05), (30, 30), (300, 300)],
                     [-0.1, -0.05, 5, 100])

    print "\nDoS attack durations (in circs) at [success_rate, dos_success_rate, path_bias_pct, scale_thresh]:"
    print brute_force(lambda x,y: x>y,
                     dos_attack_test,
                     #dos_attack_test(g, num_circs, success_rate, dos_success_rate, path_bias_pct):
                     #false_positive_test(num_circs, success_rate, scale_circs, path_bias_pct):
                     [(0.80, 0.80), (0.25,0.25), (30, 30), (200, 1000)],
                     [-0.1, -0.1, 5, 100])

    print "\nDoS attack durations (in circs) at [success_rate, dos_success_rate, path_bias_pct, scale_thresh]:"
    print brute_force(lambda x,y: x>y,
                     dos_attack_test,
                     #dos_attack_test(g, num_circs, success_rate, dos_success_rate, path_bias_pct):
                     #false_positive_test(num_circs, success_rate, scale_circs, path_bias_pct):
                     [(0.80, 0.80), (0.05,0.05), (30, 30), (200, 1000)],
                     [-0.1, -0.1, 5, 100])



if __name__ == "__main__":
  main() #sys.argv)
