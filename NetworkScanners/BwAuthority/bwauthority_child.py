#!/usr/bin/env python
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
import threading
import ConfigParser
import sqlalchemy
import sets
import re
import ssl
import random

sys.path.append("../../")

from TorCtl.TorUtil import plog
from aggregate import write_file_list

# WAAAYYYYYY too noisy.
#import gc
#gc.set_debug(gc.DEBUG_COLLECTABLE|gc.DEBUG_UNCOLLECTABLE|gc.DEBUG_INSTANCES|gc.DEBUG_OBJECTS)
 
from TorCtl import ScanSupport,PathSupport,SQLSupport,TorCtl,TorUtil

sys.path.append("../libs")
# Make our SocksiPy use our socket
__origsocket = socket.socket
socket.socket = PathSupport.SmartSocket
from SocksiPy import socks
socket.socket = __origsocket

user_agent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.0.3705; .NET CLR 1.1.4322)"

# Note these urls should be https due to caching considerations.
# If you really must make them http, be sure to change exit_ports to [80]
# below, or else the scan will not finish.
# Doesn't work: "https://38.229.70.2/"
urls =         ["https://38.229.72.16/bwauth.torproject.org/"]


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
      exit_ports=[443],
      order_by_ratio=True, # XXX: may be a poor idea for PID control?
      min_exits=10)

# exit code to indicate scan completion
# make sure to update this in bwauthority.py as well
STOP_PCT_REACHED = 9
RESTART_SLICE = 1

def read_config(filename):
  config = ConfigParser.SafeConfigParser()
  config.read(filename)

  start_pct = config.getint('BwAuthority', 'start_pct')
  stop_pct = config.getint('BwAuthority', 'stop_pct')

  nodes_per_slice = config.getint('BwAuthority', 'nodes_per_slice')
  save_every = config.getint('BwAuthority', 'save_every')
  circs_per_node = config.getint('BwAuthority', 'circs_per_node')
  min_streams = config.getint('BwAuthority', 'min_streams')
  out_dir = config.get('BwAuthority', 'out_dir')
  tor_dir = config.get('BwAuthority', 'tor_dir')
  max_fetch_time = config.getint('BwAuthority', 'max_fetch_time')

  sleep_start = config.get('BwAuthority', 'sleep_start')
  sleep_stop = config.get('BwAuthority', 'sleep_stop')

  sleep_start = tuple(map(int, sleep_start.split(":")))
  sleep_stop = tuple(map(int, sleep_stop.split(":")))

  pid_file = config.get('BwAuthority', 'pid_file')
  db_url = config.get('BwAuthority', 'db_url')

  only_unmeasured = config.getint('BwAuthority', 'only_unmeasured')
  min_unmeasured = config.getint('BwAuthority', 'min_unmeasured')

  return (start_pct,stop_pct,nodes_per_slice,save_every,
            circs_per_node,out_dir,max_fetch_time,tor_dir,
            sleep_start,sleep_stop,min_streams,pid_file,db_url,only_unmeasured,
            min_unmeasured)

def choose_url(percentile):
  # TODO: Maybe we don't want to read the file *every* time?
  # Maybe once per slice?
  # Read in the bw auths file
  # here is a fine place to make sure we have bwfiles
  try:
    f = file("./data/bwfiles", "r")
  except IOError:
    write_file_list('./data')
  lines = []
  valid = False
  for l in f.readlines():
    if l == ".\n":
      valid = True
      break
    pair = l.split()
    lines.append((int(pair[0]), pair[1]))

  if not valid:
    plog("ERROR", "File size list is invalid!")

  for (pct, fname) in lines:
    if percentile < pct:
      return random.choice(urls) + fname
  raise PathSupport.NoNodesRemain("No nodes left for url choice!")

def http_request(address):
  ''' perform an http GET-request and return 1 for success or 0 for failure '''

  request = urllib2.Request(address)
  try:
    context = ssl._create_unverified_context()
  except:
    context = None
  request.add_header('User-Agent', user_agent)

  try:
    if context:
      reply = urllib2.urlopen(request, context=context)
    else:
      reply = urllib2.urlopen(request)
    decl_length = reply.info().get("Content-Length")
    read_len = len(reply.read())
    plog("DEBUG", "Read: "+str(read_len)+" of declared "+str(decl_length))
    return 1
  except (ValueError, urllib2.URLError) as e:
    plog('ERROR', 'The http-request address ' + address + ' is malformed')
    plog('ERROR', str(e))
    return 0
  except (IndexError, TypeError) as e:
    plog('ERROR', 'An error occured while negotiating socks5 with Tor')
    return 0
  except KeyboardInterrupt:
    raise KeyboardInterrupt
  except socks.Socks5Error as e:
    if e.value[0] == 6:
      plog("NOTICE", "Tor timed out our SOCKS stream request.")
    else:
      plog('ERROR', 'An unknown HTTP error occured')
      traceback.print_exc()
    return 0
  except:
    plog('ERROR', 'An unknown HTTP error occured')
    traceback.print_exc()
    return 0

class BwScanHandler(ScanSupport.SQLScanHandler):
  def is_count_met(self, count, num_streams, position=0):
    cond = threading.Condition()
    cond._finished = True # lol python haxx. Could make subclass, but why?? :)
    def notlambda(this):
      cond.acquire()
      # TODO: Using the entry_gen router list is somewhat ghetto..
      if this.selmgr.bad_restrictions:
        plog("NOTICE",
          "Bad restrictions on last attempt. Declaring this slice finished")
      elif (this.selmgr.path_selector.entry_gen.rstr_routers and \
          this.selmgr.path_selector.exit_gen.rstr_routers):
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
        # Also run for at least 2*circs_per_node*nodes/3 successful fetches to
        # ensure we don't skip slices in the case of temporary network failure
        if cond._finished:
           num_routers = len(
                 sets.Set(this.selmgr.path_selector.entry_gen.rstr_routers
                           + this.selmgr.path_selector.exit_gen.rstr_routers))
           # If more than 35% of the 2-hop paths failed, keep going to get
           # more measurements
           if num_streams < 0.65*((num_routers*count)/2.0):
             plog("WARN", "Not enough streams yet. "+str(num_streams)+" < "+
                        str(0.65*(num_routers*count/2.0)))
             cond._finished = False
      cond.notify()
      cond.release()
    plog("DEBUG", "Checking if scan count is met...")
    cond.acquire()
    self.schedule_low_prio(notlambda)
    cond.wait()
    cond.release()
    plog("DEBUG", "Scan count met: "+str(cond._finished))
    return cond._finished

def speedrace(hdlr, start_pct, stop_pct, circs_per_node, save_every, out_dir,
              max_fetch_time, sleep_start_tp, sleep_stop_tp, slice_num,
              min_streams, sql_file, only_unmeasured):
  plog("NOTICE", "Starting slice for percentiles "+str(start_pct)+"-"+str(stop_pct))
  hdlr.set_pct_rstr(start_pct, stop_pct)

  attempt = 0
  successful = 0
  while True:
    if hdlr.is_count_met(circs_per_node, successful): break
    t0 = time.time()

    hdlr.new_exit()
    attempt += 1

    # TODO: This noise is due to a difficult to find Tor bug that
    # causes some exits to hang forever on streams :(
    # FIXME: Hrmm, should we change the reason on this? Right now,
    # 7 == TIMEOUT, which means we do not count the bandwidth of this
    # stream.. however, we count it as 'successful' below
    timer = threading.Timer(max_fetch_time, lambda: hdlr.close_streams(7))
    timer.start()

    # Always use median URL size for unmeasured nodes
    # They may be too slow..
    if only_unmeasured:
      url = choose_url(50)
    else:
      url = choose_url(start_pct)

    plog("DEBUG", "Launching stream request for url "+url+" in "+str(start_pct)+'-'+str(stop_pct) + '%')
    ret = http_request(url)
    timer.cancel()
    PathSupport.SmartSocket.clear_port_table()

    delta_build = time.time() - t0
    if delta_build >= max_fetch_time:
      plog('WARN', 'Timer exceeded limit: ' + str(delta_build) + '\n')

    build_exit = hdlr.get_exit_node()
    # FIXME: Timeouts get counted as 'sucessful' here, but do not
    # count in the SQL stats!
    if ret == 1 and build_exit:
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
      # Warning, don't remove the sql stats without changing the recompute
      # param in write_strm_bws to True
      hdlr.write_sql_stats(os.getcwd()+'/'+out_dir+'/sql-'+lo+':'+hi+"-"+str(successful)+"-"+race_time, sqlalchemy.or_(SQLSupport.RouterStats.circ_try_from > 0, SQLSupport.RouterStats.circ_try_to > 0))
      hdlr.write_strm_bws(os.getcwd()+'/'+out_dir+'/bws-'+lo+':'+hi+"-"+str(successful)+"-"+race_time, stats_filter=SQLSupport.RouterStats.strm_closed >= 1)

  plog('INFO', str(start_pct) + '-' + str(stop_pct) + '% ' + str(successful) + ' fetches took ' + str(attempt) + ' tries.')

  hdlr.close_circuits()
  hdlr.commit()
  
  lo = str(round(start_pct,1))
  hi = str(round(stop_pct,1))

  # There may be a consensus change between the point of speed
  # racing and the writing of stats causing a discrepency
  # between the immediate, current consensus result used to determine
  # termination and this average-based result.
  # So instead of using percentiles to filter here, we filter based on 
  # circuit chosen.
  hdlr.write_sql_stats(os.getcwd()+'/'+out_dir+'/sql-'+lo+':'+hi+"-done-"+time.strftime("20%y-%m-%d-%H:%M:%S"), stats_filter=sqlalchemy.or_(SQLSupport.RouterStats.circ_try_from > 0, SQLSupport.RouterStats.circ_try_to > 0))
  # Warning, don't remove the sql stats call without changing the recompute
  # param in write_strm_bws to True
  hdlr.write_strm_bws(os.getcwd()+'/'+out_dir+'/bws-'+lo+':'+hi+"-done-"+time.strftime("20%y-%m-%d-%H:%M:%S"), slice_num, stats_filter=sqlalchemy.and_(SQLSupport.RouterStats.strm_closed >= min_streams, SQLSupport.RouterStats.filt_sbw >= 0, SQLSupport.RouterStats.sbw >=0 ))
  plog('DEBUG', 'Wrote stats')
  #hdlr.save_sql_file(sql_file, os.getcwd()+"/"+out_dir+"/bw-db-"+str(lo)+":"+str(hi)+"-"+time.strftime("20%y-%m-%d-%H:%M:%S")+".sqlite")

  return successful

def main(argv):
  TorUtil.read_config(argv[1])
  (start_pct,stop_pct,nodes_per_slice,save_every,circs_per_node,out_dir,
      max_fetch_time,tor_dir,sleep_start,sleep_stop,
             min_streams,pid_file_name,db_url,only_unmeasured,
             min_unmeasured) = read_config(argv[1])
  plog("NOTICE", "Child Process Spawned...")

  # make sure necessary out_dir directory exists
  path = os.getcwd()+'/'+out_dir
  if not os.path.exists(path):
    os.makedirs(path)
 
  if pid_file_name:
    pidfd = file(pid_file_name, 'w')
    pidfd.write('%d\n' % os.getpid())
    pidfd.close()

    slice_num = int(argv[2])

    try:
      (c,hdlr) = setup_handler(out_dir, tor_dir+"/control_auth_cookie")
    except Exception, e:
      traceback.print_exc()
      plog("WARN", "Can't connect to Tor: "+str(e))
      sys.exit(STOP_PCT_REACHED)

    if db_url:
      hdlr.attach_sql_listener(db_url)
      sql_file = None
    else:
      plog("INFO", "db_url not found in config. Defaulting to sqlite")
      sql_file = os.getcwd()+'/'+out_dir+'/bwauthority.sqlite'
      #hdlr.attach_sql_listener('sqlite:///'+sql_file)
      hdlr.attach_sql_listener('sqlite://')

    # set SOCKS proxy
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TorUtil.tor_host, TorUtil.tor_port)
    socket.socket = socks.socksocket
    plog("INFO", "Set socks proxy to "+TorUtil.tor_host+":"+str(TorUtil.tor_port))

    hdlr.schedule_selmgr(lambda s: setattr(s, "only_unmeasured", only_unmeasured))

    hdlr.wait_for_consensus()

    # Now that we have the consensus, we shouldn't need to listen
    # for new consensus events.
    c.set_events([TorCtl.EVENT_TYPE.STREAM,
          TorCtl.EVENT_TYPE.BW,
          TorCtl.EVENT_TYPE.CIRC,
          TorCtl.EVENT_TYPE.STREAM_BW], True)

    # We should go to sleep if there are less than 5 unmeasured nodes after
    # consensus update
    if min_unmeasured and hdlr.get_unmeasured() < min_unmeasured:
      plog("NOTICE", "Less than "+str(min_unmeasured)+" unmeasured nodes ("+str(hdlr.get_unmeasured())+"). Sleeping for a bit")
      time.sleep(3600) # Until next consensus arrives
      plog("NOTICE", "Woke up from waiting for more unmeasured nodes.  Requesting slice restart.")
      sys.exit(RESTART_SLICE)

    pct_step = hdlr.rank_to_percent(nodes_per_slice)
    plog("INFO", "Percent per slice is: "+str(pct_step))
    if pct_step > 100: pct_step = 100

    # check to see if we are done
    if (slice_num * pct_step + start_pct > stop_pct):
        plog('NOTICE', 'Child stop point %s reached. Exiting with %s' % (stop_pct, STOP_PCT_REACHED))
        sys.exit(STOP_PCT_REACHED)

    successful = speedrace(hdlr, slice_num*pct_step + start_pct, (slice_num + 1)*pct_step + start_pct, circs_per_node,
              save_every, out_dir, max_fetch_time, sleep_start, sleep_stop, slice_num,
              min_streams, sql_file, only_unmeasured)

    # For debugging memory leak..
    #TorUtil.dump_class_ref_counts(referrer_depth=1)

    # TODO: Change pathlen to 3 and kill exit+ConserveExit restrictions
    # And record circ failure rates..

    #circ_measure(hdlr, pct, pct+pct_step, circs_per_node, save_every, 
    #  out_dir, max_fetch_time, sleep_start, sleep_stop, slice_num, sql_file)

    # XXX: Hack this to return a codelen double the slice size on failure?
    plog("INFO", "Slice success count: "+str(successful))
    if successful == 0:
      plog("WARN", "Slice success count was ZERO!")

    sys.exit(0)

def ignore_streams(c,hdlr):
  for stream in c.get_info("stream-status")['stream-status'].rstrip("\n").split("\n"):
    m = re.match("(?P<sid>\d*)\s(?P<status>\S*)\s(?P<cid>\d*)\s(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<port>\d{1,5})",stream)
    if m:
      f = m.groupdict()
    else:
      return # no streams
    s = PathSupport.Stream(int(f['sid']), f['host'], int(f['port']), 0)
    plog("DEBUG", "Ignoring foreign stream: %s" % f['sid'])
    s.ignored = True
    hdlr.streams[s.strm_id] = s

def cleanup():
  plog("DEBUG", "Child Process Exiting...")

def setup_handler(out_dir, cookie_file):
  plog('INFO', 'Connecting to Tor at '+TorUtil.control_host+":"+str(TorUtil.control_port))
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((TorUtil.control_host,TorUtil.control_port))
  c = PathSupport.Connection(s)
  #c.debug(file(out_dir+"/control.log", "w", buffering=0))
  c.authenticate_cookie(file(cookie_file, "r"))
  h = BwScanHandler(c, __selmgr,
                    strm_selector=PathSupport.SmartSocket.StreamSelector)

  # ignore existing streams
  ignore_streams(c,h)
  c.set_event_handler(h)
  #c.set_periodic_timer(2.0, "PULSE")

  c.set_events([TorCtl.EVENT_TYPE.STREAM,
          TorCtl.EVENT_TYPE.BW,
          TorCtl.EVENT_TYPE.NEWCONSENSUS,
          TorCtl.EVENT_TYPE.NEWDESC,
          TorCtl.EVENT_TYPE.CIRC,
          TorCtl.EVENT_TYPE.STREAM_BW], True)

  atexit.register(cleanup)
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
  except SystemExit, e:
    sys.exit(e)
  except Exception, e:
    plog('ERROR', "An unexpected error occured.")
    traceback.print_exc()
