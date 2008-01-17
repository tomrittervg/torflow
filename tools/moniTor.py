#!/usr/bin/env python
#
#
# This is a "top-like" interface for Tor information
# It's goal at the start is to just tell you basic information
# In the future, you may be able to control Tor with it.
#
# See this for some of the original ideas:
# http://archives.seul.org/or/dev/Jan-2008/msg00005.html
#
#	A typical output of moniTor could look like this (with some fake data
#	for the purpose of this example):
#
#	~  Name/ID: gabelmoo 6833 3D07 61BC F397 A587 A0C0 B963 E4A9 E99E C4D3
#	~  Version: 0.2.0.15-alpha-dev (r13077) on Linux x86_64
#	~  Config: /home/tor/gabelmoo/torrc,     Exit policy: no exit allowed
#	~  IP address: 88.198.7.215,    OR port:  443,    Dir port:   80
#
#	~  CPU:  9.0% this tor,  3.4% other processes, 87.6% idle
#	~  Mem: 49.9% this tor,  2.0% other processes, 48.1% free
#	~  Connections: 1090 OR conns,  320 Dir conns
#	~  Bandwidth:  1.2 MB/s current,  1.3 MB/s avg
#
#	~  Recent events (see also /home/tor/gabelmoo/monitor.log):
#	~  14:30:01 [warn] Consensus does not include configured authority 'moria
#	~  14:30:01 [warn] Consensus does not include configured authority 'ides'
#	~  14:30:01 [warn] 0 unknown, 0 missing key, 2 good, 0 bad, 1 no signatur
#	~  14:30:01 [warn] Not enough info to publish pending consensus
#


__author__    = "Jacob Appelbaum"
__version__   = "0.1-2008_01_16"
__copyright__ = "http://www.torproject.org/Jacob Appelbaum 2008"

import curses
import time
from TorCtl import *

# Parse authenticate string from file here

#moniTorConf = "/etc/moniTor.conf"
#authSecret = open(moniTorConf).read().strip()
authSecret = ""

def parse_config():

    #moniTorConf = "/etc/moniTor.conf"
    #authSecret = open(moniTorConf).read().strip()
    authSecret = ""

    return

def create_oracle(host,port):
    """ Create a useful TorCtl object
    """
    print "I'm going to connect to %s and connect to port %i" %(sh,sp)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    oracle = Connection(s)
    oracle_thread = oracle.launch_thread()
    oracle.authenticate(authSecret)

    return oracle, oracle_thread

# Much like run_example from TorCtl
def collect_status(oracle):
    """ A basic loop for collecting static information from our TorCtl object
    """
    # add name/id, exit policy, or-port, dir-port

    static_keys = ['version', 'config-file', 'address', 'fingerprint', 'exit-policy/default', 'accounting/enabled']
    static_info = dict([(key, oracle.get_info(key)[key]) for key in static_keys])

    # Dynamic information can be collected by using our returned socket
    return static_info, static_keys

if __name__ == '__main__':
  if len(sys.argv) > 1:
    print "Syntax: ",sys.argv[0]
    sys.exit(1)
  else:
    sys.argv.append("localhost:9051")

  parse_config()
  sh,sp = parseHostAndPort(sys.argv[1])

  torctl_oracle, torctl_oracle_thread = create_oracle(sh,sp)
  static_info, static_keys, = collect_status(torctl_oracle) 

  # Number of connections, current bw
  dynamic_keys = ['version', 'config-file', 'address', 'fingerprint']

  torctl_oracle.set_event_handler(DebugEventHandler())
  torctl_oracle.set_events([EVENT_TYPE.STREAM, EVENT_TYPE.CIRC,
          EVENT_TYPE.NS, EVENT_TYPE.NEWDESC,
          EVENT_TYPE.ORCONN, EVENT_TYPE.BW], True)


  while True:
      # Populate the dynamic info each run
      dynamic_info = dict([(key, torctl_oracle.get_info(key)[key]) for key in dynamic_keys])

      # Now we can draw a few interesting things to the screen
      for key in static_info:
          print key + " is " + static_info[key]

      for key in dynamic_info:
          print key + " is " + dynamic_info[key]

      torctl_oracle_thread.join()

      time.sleep(1)
      # So ghetto, so ghetto!
      os.system('clear')

