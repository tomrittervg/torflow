#!/usr/bin/python
#
# 2009 Mike Perry, Karsten Loesing

"""
Speedracer

Speedracer continuously requests the Tor design paper over the Tor network
and measures how long circuit building and downloading takes.
"""

import atexit
import socket
from time import time,strftime
import sys
import urllib2
import os
import traceback
import copy
import threading

sys.path.append("../../")

from TorCtl.TorUtil import plog

from TorCtl.TorUtil import control_port, control_host, tor_port, tor_host, control_pass

from TorCtl import PathSupport,SQLSupport,TorCtl,TorUtil

sys.path.append("../libs")
from SocksiPy import socks

user_agent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.0.3705; .NET CLR 1.1.4322)"

# Some constants for measurements
url = "https://svn.torproject.org/svn/tor/trunk/doc/design-paper/tor-design.pdf"

# XXX: Make this into easy-to-select ranges for paralelization
start_pct = 0
stop_pct = 78
# Slice size:
pct_step = 3
# Number of fetches per slice:
count = 250
save_every = 10

# Do NOT modify this object directly after it is handed to PathBuilder
# Use PathBuilder.schedule_selmgr instead.
# (Modifying the arguments here is OK)
__selmgr = PathSupport.SelectionManager(
      pathlen=2,
      order_exits=False,
      percent_fast=15,
      percent_skip=0,
      min_bw=1024,
      use_all_exits=False,
      uniform=True,
      use_exit=None,
      use_guards=False)

# Note: be careful writing functions for this class. Remember that
# the PathBuilder has its own thread that it recieves events on
# independent from your thread that calls into here.
class BwScanHandler(PathSupport.PathBuilder):
  def get_exit_node(self):
    return copy.copy(self.last_exit) # GIL FTW

  def attach_sql_listener(self, db_uri):
    plog("DEBUG", "Got sqlite: "+db_uri)
    SQLSupport.setup_db(db_uri, echo=False, drop=True)
    self.add_event_listener(SQLSupport.ConsensusTrackerListener())
    self.add_event_listener(SQLSupport.StreamListener())

  def write_sql_stats(self, percent_skip, percent_fast, rfilename=None):
    if not rfilename:
      rfilename="./data/stats/sql-"+time.strftime("20%y-%m-%d-%H:%M:%S")
    cond = threading.Condition()
    def notlambda(h):
      cond.acquire()
      SQLSupport.RouterStats.write_stats(file(rfilename, "w"),
                            percent_skip, percent_fast,
                            order_by=SQLSupport.RouterStats.sbw,
                            recompute=True)
      cond.notify()
      cond.release()
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()

  def write_strm_bws(self, percent_skip, percent_fast, rfilename=None):
    if not rfilename:
      rfilename="./data/stats/bws-"+time.strftime("20%y-%m-%d-%H:%M:%S")
    cond = threading.Condition()
    def notlambda(h):
      cond.acquire()
      SQLSupport.RouterStats.write_bws(file(rfilename, "w"),
                            percent_skip, percent_fast,
                            order_by=SQLSupport.RouterStats.sbw,
                            recompute=False) # XXX: Careful here..
      cond.notify()
      cond.release()
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()

  def set_pct_rstr(self, percent_skip, percent_fast):
    def notlambda(sm):
      sm.percent_fast=percent_fast
      sm.percent_skip=percent_skip
    self.schedule_selmgr(notlambda)

  # TODO: Do we really want to totally reset stats, or can we update
  # the SQL stats to just drop all but the N most recent streams for each
  # node..
  def reset_stats(self):
    def notlambda(this): this.reset()
    self.schedule_low_prio(notlambda)

  def commit(self):
    def notlambda(this): this.run_all_jobs = True
    self.schedule_immediate(notlambda)

  def close_circuits(self):
    def notlambda(this): this.close_all_circuits()
    self.schedule_immediate(notlambda)

  def new_exit(self):
    cond = threading.Condition()
    def notlambda(this):
      cond.acquire()
      this.new_nym = True # GIL hack
      lines = this.c.sendAndRecv("SIGNAL CLEARDNSCACHE\r\n")
      for _,msg,more in lines:
        plog("DEBUG", msg)
      cond.notify()
      cond.release()
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()

  def is_count_met(self, count, position=0):
    # TODO: wait on condition and check all routerstatuses
    pass


def http_request(address):
  ''' perform an http GET-request and return 1 for success or 0 for failure '''

  request = urllib2.Request(address)
  request.add_header('User-Agent', user_agent)

  try:
    reply = urllib2.urlopen(request)
    decl_length = reply.info().get("Content-Length")
    read_len = len(reply.read())
    plog("DEBUG", "Read: "+str(read_len)+" of declared "+str(decl_length))
    return 1
  except (ValueError, urllib2.URLError):
    plog('ERROR', 'The http-request address ' + address + ' is malformed')
    return 0
  except (IndexError, TypeError):
    plog('ERROR', 'An error occured while negotiating socks5 with Tor')
    return 0
  except KeyboardInterrupt:
    raise KeyboardInterrupt
  except:
    plog('ERROR', 'An unknown HTTP error occured')
    traceback.print_exc()
    return 0 

def speedrace(hdlr, skip, pct):
  hdlr.set_pct_rstr(skip, pct)

  attempt = 0
  successful = 0
  while successful < count:
    hdlr.new_exit()
    
    attempt += 1
    
    t0 = time()
    ret = http_request(url)
    delta_build = time() - t0
    if delta_build >= 550.0:
      plog('NOTICE', 'Timer exceeded limit: ' + str(delta_build) + '\n')

    build_exit = hdlr.get_exit_node()
    if ret == 1:
      successful += 1
      plog('DEBUG', str(skip) + '-' + str(pct) + '% circuit build+fetch took ' + str(delta_build) + ' for ' + str(build_exit))
    else:
      plog('DEBUG', str(skip) + '-' + str(pct) + '% circuit build+fetch failed for ' + str(build_exit))

    if ret and successful and successful != count \
           and (successful % save_every) == 0:
      race_time = strftime("20%y-%m-%d-%H:%M:%S")
      hdlr.close_circuits()
      hdlr.write_sql_stats(skip, pct, os.getcwd()+'/out.1/sql-'+str(skip)+':'+str(pct)+"-"+str(successful)+"-"+race_time)
      hdlr.write_strm_bws(skip, pct, os.getcwd()+'/out.1/bws-'+str(skip)+':'+str(pct)+"-"+str(successful)+"-"+race_time)
      hdlr.commit()

  plog('INFO', str(skip) + '-' + str(pct) + '% ' + str(count) + ' fetches took ' + str(attempt) + ' tries.')

def main(argv):
  # XXX: Parse options for this file and also for output dir
  TorUtil.read_config("bwauthority.cfg.1") 
  
  try:
    (c,hdlr) = setup_handler()
  except Exception, e:
    plog("WARN", "Can't connect to Tor: "+str(e))

  hdlr.attach_sql_listener('sqlite:///'+os.getcwd()+'/out.1/speedracer.sqlite')

  # set SOCKS proxy
  socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, tor_host, tor_port)
  socket.socket = socks.socksocket

  while True:
    pct = start_pct
    plog('INFO', 'Beginning time loop')
    
    while pct < stop_pct:
      hdlr.reset_stats()
      hdlr.commit()
      plog('DEBUG', 'Reset stats')

      speedrace(hdlr, pct, pct + pct_step)

      plog('DEBUG', 'speedroced')
      hdlr.close_circits()
      hdlr.write_sql_stats(pct, pct+pct_step, os.getcwd()+'/out.1/sql-'+str(pct) + ':' + str(pct + pct_step)+"-"+str(count)+"-"+strftime("20%y-%m-%d-%H:%M:%S"))
      hdlr.write_strm_bws(pct, pct+pct_step, os.getcwd()+'/out.1/bws-'+str(pct)+':'+str(pct+pct_step)+"-"+str(count)+"-"+strftime("20%y-%m-%d-%H:%M:%S"))
      plog('DEBUG', 'Wrote stats')
      pct += pct_step
      hdlr.commit() # XXX: Right place for this?

def cleanup(c, f):
  plog("INFO", "Resetting __LeaveStreamsUnattached=0 and FetchUselessDescriptors="+f)
  try:
    c.set_option("__LeaveStreamsUnattached", "0")
    c.set_option("FetchUselessDescriptors", f)
  except TorCtl.TorCtlClosed:
    pass

def setup_handler():
  plog('INFO', 'Connecting to Tor...')
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((control_host,control_port))
  c = PathSupport.Connection(s)
  #c.debug(file("control.log", "w", buffering=0))
  c.authenticate(control_pass)
  h = BwScanHandler(c, __selmgr)

  c.set_event_handler(h)

  c.set_events([TorCtl.EVENT_TYPE.STREAM,
          TorCtl.EVENT_TYPE.BW,
          TorCtl.EVENT_TYPE.NEWCONSENSUS,
          TorCtl.EVENT_TYPE.NEWDESC,
          TorCtl.EVENT_TYPE.CIRC,
          TorCtl.EVENT_TYPE.STREAM_BW], True)

  c.set_option("__LeaveStreamsUnattached", "1")
  f = c.get_option("FetchUselessDescriptors")[0][1]
  c.set_option("FetchUselessDescriptors", "1")
  atexit.register(cleanup, *(c, f))
  return (c,h)

# initiate the program
if __name__ == '__main__':
  try:
    main(sys.argv)
  except KeyboardInterrupt:
    plog('INFO', "Ctrl + C was pressed. Exiting ... ")
    traceback.print_exc()
  except Exception, e:
    plog('ERROR', "An unexpected error occured.")
    traceback.print_exc()
