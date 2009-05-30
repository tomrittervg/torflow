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
import time
import sys
import urllib2
import os
import traceback
import copy
import shutil
import threading
import ConfigParser

sys.path.append("../../")

from TorCtl.TorUtil import plog


from TorCtl import PathSupport,SQLSupport,TorCtl,TorUtil

sys.path.append("../libs")
from SocksiPy import socks

user_agent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.0.3705; .NET CLR 1.1.4322)"

# Note these urls should be https due to caching considerations.
# If you really must make them http, be sure to change exit_ports to [80]
# below, or else the scan will not finish.
# As the network balances, these can become more uniform in size
#          cutoff percent                URL
urls =         [(10,          "https://128.174.236.117/4096k"),
                (20,          "https://128.174.236.117/2048k"),
                (30,          "https://128.174.236.117/1024k"),
                (60,          "https://128.174.236.117/512k"),
                (75,          "https://128.174.236.117/256k"),
                (100,         "https://128.174.236.117/128k")]


# Do NOT modify this object directly after it is handed to PathBuilder
# Use PathBuilder.schedule_selmgr instead.
# (Modifying the arguments here is OK)
__selmgr = PathSupport.SelectionManager(
      pathlen=2,
      order_exits=False,
      percent_fast=100,
      percent_skip=0,
      min_bw=1024,
      use_all_exits=False,
      uniform=True,
      use_exit=None,
      use_guards=False,
      exit_ports=[443])

def read_config(filename):
  config = ConfigParser.SafeConfigParser()
  config.read(filename)

  start_pct = config.getint('BwAuthority', 'start_pct')
  stop_pct = config.getint('BwAuthority', 'stop_pct')

  nodes_per_slice = config.getint('BwAuthority', 'nodes_per_slice')
  save_every = config.getint('BwAuthority', 'save_every')
  circs_per_node = config.getint('BwAuthority', 'circs_per_node')
  out_dir = config.get('BwAuthority', 'out_dir')
  tor_dir = config.get('BwAuthority', 'tor_dir')
  max_fetch_time = config.getint('BwAuthority', 'max_fetch_time')

  return (start_pct,stop_pct,nodes_per_slice,save_every,
            circs_per_node,out_dir,max_fetch_time,tor_dir)

def choose_url(percentile):
  for (pct, url) in urls:
    if percentile < pct:
      return url
      #return "https://86.59.21.36/torbrowser/dist/tor-im-browser-1.2.0_ru_split/tor-im-browser-1.2.0_ru_split.part01.exe"
  raise PathSupport.NoNodesRemain("No nodes left for url choice!")

# Note: be careful writing functions for this class. Remember that
# the PathBuilder has its own thread that it recieves events on
# independent from your thread that calls into here.
class BwScanHandler(PathSupport.PathBuilder):
  def get_exit_node(self):
    return copy.copy(self.last_exit) # GIL FTW

  def attach_sql_listener(self, db_uri):
    plog("DEBUG", "Got sqlite: "+db_uri)
    SQLSupport.setup_db(db_uri, echo=False, drop=True)
    self.sql_consensus_listener = SQLSupport.ConsensusTrackerListener()
    self.add_event_listener(self.sql_consensus_listener)
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
    def notlambda(this):
      cond.acquire()
      f=file(rfilename, "w")
      f.write("low="+str(int(round((percent_skip*len(this.sorted_r))/100.0,0)))
             +" hi="+str(int(round((percent_fast*len(this.sorted_r))/100.0,0)))
             +"\n")
      SQLSupport.RouterStats.write_bws(f, percent_skip, percent_fast,
                            order_by=SQLSupport.RouterStats.sbw,
                            recompute=False) # XXX: Careful here..
      f.close()
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

  def reset_stats(self):
    def notlambda(this): 
      this.reset()
    self.schedule_low_prio(notlambda)

  def save_sql_file(self, sql_file, new_file):
    cond = threading.Condition()
    def notlambda(this):
      cond.acquire()
      SQLSupport.tc_session.close()
      try:
        shutil.copy(sql_file, new_file)
      except Exception,e:
        plog("WARN", "Error moving sql file: "+str(e))
      SQLSupport.reset_all()
      cond.notify()
      cond.release()
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()

  def commit(self):
    plog("INFO", "Scanner committing jobs...")
    cond = threading.Condition()
    def notlambda2(this):
      cond.acquire()
      this.run_all_jobs = False
      plog("INFO", "Commit done.")
      cond.notify()
      cond.release()

    def notlambda1(this):
      plog("INFO", "Committing jobs...")
      this.run_all_jobs = True
      self.schedule_low_prio(notlambda2)

    cond.acquire()
    self.schedule_immediate(notlambda1)

    cond.wait()
    cond.release()
    plog("INFO", "Scanner commit done.")

  def close_circuits(self):
    cond = threading.Condition()
    def notlambda(this):
      cond.acquire()
      this.close_all_circuits()
      cond.notify()
      cond.release()
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()

  def close_streams(self, reason):
    cond = threading.Condition()
    def notlambda(this):
      cond.acquire()
      this.close_all_streams(reason)
      cond.notify()
      cond.release()
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()

  def new_exit(self):
    cond = threading.Condition()
    def notlambda(this):
      cond.acquire()
      this.new_nym = True
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
    cond = threading.Condition()
    cond._finished = True # lol python haxx. Could make subclass, but why?? :)
    def notlambda(this):
      cond.acquire()
      # TODO: Using the entry_gen router list is somewhat ghetto..
      for r in this.selmgr.path_selector.entry_gen.rstr_routers:
        if r._generated[position] < count:
          cond._finished = False
          plog("DEBUG", "Entry router "+r.idhex+"="+r.nickname+" not done: "+str(r._generated[position])+", down: "+str(r.down)+", OK: "+str(this.selmgr.path_selector.entry_gen.rstr_list.r_is_ok(r))+", sorted_r: "+str(r in this.sorted_r))
          # XXX:
          #break
      for r in this.selmgr.path_selector.exit_gen.rstr_routers:
        if r._generated[position] < count:
          cond._finished = False
          plog("DEBUG", "Exit router "+r.idhex+"="+r.nickname+" not done: "+str(r._generated[position])+", down: "+str(r.down)+", OK: "+str(this.selmgr.path_selector.exit_gen.rstr_list.r_is_ok(r))+", sorted_r: "+str(r in this.sorted_r))
          # XXX:
          #break
      cond.notify()
      cond.release()
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()
    return cond._finished

  def rank_to_percent(self, rank):
    cond = threading.Condition()
    def notlambda(this):
      cond.acquire()
      cond._pct = (100.0*rank)/len(this.sorted_r) # lol moar haxx
      cond.notify()
      cond.release()
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()
    return cond._pct

  def percent_to_rank(self, pct):
    cond = threading.Condition()
    def notlambda(this):
      cond.acquire()
      cond._rank = int(round((pct*len(this.sorted_r))/100.0,0)) # lol moar haxx
      cond.notify()
      cond.release()
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()
    return cond._rank

  def wait_for_consensus(self):
    cond = threading.Condition()
    def notlambda(this):
      if this.sql_consensus_listener.last_desc_at \
                 != SQLSupport.ConsensusTrackerListener.CONSENSUS_DONE:
        this.sql_consensus_listener.wait_for_signal = False
        plog("INFO", "Waiting on consensus result: "+str(this.run_all_jobs))
        this.schedule_low_prio(notlambda)
      else:
        cond.acquire()
        this.sql_consensus_listener.wait_for_signal = True
        cond.notify()
        cond.release()
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()
    plog("INFO", "Consensus OK")

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

def speedrace(hdlr, start_pct, stop_pct, circs_per_node, save_every, out_dir, 
              max_fetch_time):
  hdlr.set_pct_rstr(start_pct, stop_pct)

  attempt = 0
  successful = 0
  while not hdlr.is_count_met(circs_per_node):
    hdlr.wait_for_consensus()

    # Check local time. Do not scan between 01:30 and 05:30 local time
    # XXX: -> config file?
    lt = time.localtime()
    sleep_start = time.mktime(lt[0:3]+(1,30,0,0,0)+(lt[-1],))
    sleep_stop = time.mktime(lt[0:3]+(5,30,0,0,0)+(lt[-1],))
    t0 = time.time()
    if sleep_start <= t0 and t0 <= sleep_stop:
      plog("NOTICE", "It's bedtime. Sleeping for "+str(round((sleep_stop-t0)/3600.0,1))+"h")
      #time.sleep(sleep_stop - t0)

    hdlr.new_exit()
    attempt += 1
    
    # FIXME: This noise is due to a difficult to find Tor bug that
    # causes some exits to hang forever on streams :(
    timer = threading.Timer(max_fetch_time, lambda: hdlr.close_streams(7))
    timer.start()
    url = choose_url(start_pct)
    plog("DEBUG", "Launching stream request for url "+url+" in "+str(start_pct)+'-'+str(stop_pct) + '%')
    ret = http_request(url)
    timer.cancel()

    delta_build = time.time() - t0
    if delta_build >= max_fetch_time:
      plog('WARN', 'Timer exceeded limit: ' + str(delta_build) + '\n')

    build_exit = hdlr.get_exit_node()
    if ret == 1:
      successful += 1
      plog('DEBUG', str(start_pct) + '-' + str(stop_pct) + '% circuit build+fetch took ' + str(delta_build) + ' for ' + str(build_exit))
    else:
      plog('DEBUG', str(start_pct)+'-'+str(stop_pct)+'% circuit build+fetch failed for ' + str(build_exit))

    if save_every and ret and successful and (successful % save_every) == 0:
      race_time = time.strftime("20%y-%m-%d-%H:%M:%S")
      hdlr.close_circuits()
      hdlr.commit()
      lo = str(round(start_pct,1))
      hi = str(round(stop_pct,1))
      hdlr.write_sql_stats(start_pct, stop_pct, os.getcwd()+'/'+out_dir+'/sql-'+lo+':'+hi+"-"+str(successful)+"-"+race_time)
      hdlr.write_strm_bws(start_pct, stop_pct, os.getcwd()+'/'+out_dir+'/bws-'+lo+':'+hi+"-"+str(successful)+"-"+race_time)

  plog('INFO', str(start_pct) + '-' + str(stop_pct) + '% ' + str(successful) + ' fetches took ' + str(attempt) + ' tries.')

def main(argv):
  TorUtil.read_config(argv[1]) 
  (start_pct,stop_pct,nodes_per_slice,save_every,
         circs_per_node,out_dir,max_fetch_time,tor_dir) = read_config(argv[1])
 
  try:
    (c,hdlr) = setup_handler(tor_dir+"/control_auth_cookie")
  except Exception, e:
    traceback.print_exc()
    plog("WARN", "Can't connect to Tor: "+str(e))

  sql_file = os.getcwd()+'/'+out_dir+'/bwauthority.sqlite'
  hdlr.attach_sql_listener('sqlite:///'+sql_file)

  # set SOCKS proxy
  socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TorUtil.tor_host, TorUtil.tor_port)
  socket.socket = socks.socksocket
  plog("INFO", "Set socks proxy to "+TorUtil.tor_host+":"+str(TorUtil.tor_port))

  while True:
    pct = start_pct
    plog('INFO', 'Beginning time loop')
    
    while pct < stop_pct:
      pct_step = hdlr.rank_to_percent(nodes_per_slice)
      hdlr.reset_stats()
      hdlr.commit()
      plog('DEBUG', 'Reset stats')

      speedrace(hdlr, pct, pct+pct_step, circs_per_node, save_every, out_dir,
                max_fetch_time)

      plog('DEBUG', 'speedroced')
      hdlr.close_circuits()
      hdlr.commit()

      lo = str(round(pct,1))
      hi = str(round(pct+pct_step,1))
      
      hdlr.write_sql_stats(pct, pct+pct_step, os.getcwd()+'/'+out_dir+'/sql-'+lo+':'+hi+"-done-"+time.strftime("20%y-%m-%d-%H:%M:%S"))
      hdlr.write_strm_bws(pct, pct+pct_step, os.getcwd()+'/'+out_dir+'/bws-'+lo+':'+hi+"-done-"+time.strftime("20%y-%m-%d-%H:%M:%S"))
      plog('DEBUG', 'Wrote stats')
      pct += pct_step
      hdlr.save_sql_file(sql_file, os.getcwd()+"/"+out_dir+"/db-"+str(lo)+":"+str(hi)+"-"+time.strftime("20%y-%m-%d-%H:%M:%S")+".sqlite")

def cleanup(c, f):
  plog("INFO", "Resetting __LeaveStreamsUnattached=0 and FetchUselessDescriptors="+f)
  try:
    c.set_option("__LeaveStreamsUnattached", "0")
    c.set_option("FetchUselessDescriptors", f)
  except TorCtl.TorCtlClosed:
    pass

def setup_handler(cookie_file):
  plog('INFO', 'Connecting to Tor at '+TorUtil.control_host+":"+str(TorUtil.control_port))
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((TorUtil.control_host,TorUtil.control_port))
  c = PathSupport.Connection(s)
  #c.debug(file("control.log", "w", buffering=0))
  #c.authenticate()
  c.authenticate_cookie(file(cookie_file, "r"))
  h = BwScanHandler(c, __selmgr)

  c.set_event_handler(h)
  #c.set_periodic_timer(2.0, "PULSE")

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

def usage(argv):
  print "Usage: "+argv[0]+" <configfile>"
  return

# initiate the program
if __name__ == '__main__':
  try:
    if len(sys.argv) < 2: usage(sys.argv)
    else: main(sys.argv)
  except KeyboardInterrupt:
    plog('INFO', "Ctrl + C was pressed. Exiting ... ")
    traceback.print_exc()
  except Exception, e:
    plog('ERROR', "An unexpected error occured.")
    traceback.print_exc()
