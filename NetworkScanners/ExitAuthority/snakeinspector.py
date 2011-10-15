#!/usr/bin/python2.6

import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders

import operator
import os
import sys
import time
import traceback

import getopt
import getpass
import socket
import struct

from libsoat import *
from soat_config import *

sys.path.append("../../")
try:
    import TorCtl.TorUtil
except ImportError:
    from os import getcwd, path
    print "TorCtl not found in %s. Did you run torflow.git/add_torctl.sh?" % path.abspath(getcwd()+'../..')
    print "Exiting..."
    exit()

TorCtl.TorUtil.loglevel="INFO"

if TorCtl.TorUtil.loglevels[TorCtl.TorUtil.loglevel] > TorCtl.TorUtil.loglevels["INFO"]:
  # Kill stderr (jsdiffer and exception noise) if our loglevel is above INFO
  sys.stderr = file("/dev/null", "w")

def usage(argv=None):

  print "Usage: "+argv[0]+" with 0 or more of the following filters: "
  print "  --dir <datadir>"
  print "  --file <.result file>"
  print "  --exit <idhex>"
  print "  --after <timestamp as string (eg. \"Thu Jan 1 00:00:00 1970\")>"
  print "  --before <timestamp as string (eg. \"Mon Jan 19 03:14:07 2038\")>"
  print "  --finishedafter <timestamp as string>"
  print "  --finishedbefore <timestamp as string>"
  print "  --reason <soat failure reason>    # may be repeated"
  print "  --noreason <soat failure reason>  # may be repeated"
  print "  --proto <protocol>"
  print "  --resultfilter <TestResult class name>"
  print "  --statuscode <'Failure' or 'Inconclusive'>"
  print "  --siterate <integer n; print result if <n% of exits failed that site>"
  print "  --exitrate <integer n; print result if the exit failed >n% of sites>"
  print "  --sortby <'proto' or 'url' or 'exit' or 'reason'>"
  print "  --falsepositives"
  print "  --verbose"
  sys.exit(1)

class SIConf(object):
  def __init__(self, argv=None):
    # FIXME: make all these repeatable
    self.use_dir="./data/"
    self.use_file=None
    self.node=None
    self.reasons=[]
    self.noreasons=[]
    self.statuscode=2
    self.verbose=1
    self.proto=None
    self.resultfilter=None
    self.before = 0xffffffff
    self.after = 0
    self.finishedbefore = 0xffffffff
    self.finishedafter = 0
    self.finished = False
    self.sortby="proto"
    self.siterate = 100
    self.exitrate = 0
    self.falsepositives=False
    self.send_email = False
    self.confirmed = False
    self.cron_interval = 0
    if argv:
      self.getargs(argv)

  def getargs(self, argv):
    try:
      opts,args = getopt.getopt(argv[1:],"d:f:x:r:n:a:b:t:p:o:s:h:Fmcv",
               ["dir=", "file=", "exit=", "reason=", "resultfilter=", "proto=",
                "verbose", "statuscode=", "siterate=", "exitrate=", "sortby=",
                "noreason=", "after=", "before=", "finishedafter=",
                "finishedbefore=", "croninterval=", "falsepositives",
                "email", "confirmed","help"])
    except getopt.GetoptError,err:
      print str(err)
      usage(argv)
    for o,a in opts:
      if o == '-h' or o == '--help':
          usage(argv)
      elif o == '-d' or o == '--dir':
        self.use_dir = a
      elif o == '-f' or o == '--file':
        self.use_file = a
      elif o == '-x' or o == '--exit':
        self.node = a
      elif o == '-r' or o == '--reason':
        self.reasons.append(a)
      elif o == '-n' or o == '--noreason':
        self.noreasons.append(a)
      elif o == '-a' or o == '--after':
        self.after = time.mktime(time.strptime(a))
      elif o == '-b' or o == '--before':
        self.before = time.mktime(time.strptime(a))
      elif o == '--finishedbefore':
        self.finishedbefore = time.mktime(time.strptime(a))
        self.finished = True
      elif o == '--finishedafter':
        self.finishedafter = time.mktime(time.strptime(a))
        self.finished = True
      elif o == '--croninterval':
        self.cron_interval = int(a)*3600
      elif o == '-t' or o == '--resultfilter':
        self.resultfilter = a
      elif o == '-p' or o == '--proto':
        self.proto = a
      elif o == '--siterate':
        self.siterate = int(a)
      elif o == '--exitrate':
        self.exitrate = int(a)
      elif o == '-F' or o == '--falsepositives':
        self.falsepositives = True
      elif o == '-m' or o == '--email':
        self.send_email = True
      elif o == '-c' or o == '--confirmed':
        self.confirmed = True
      elif o == '-v' or o == '--verbose':
        self.verbose += 1
      elif o == '-o' or o == '--sortby':
        if a not in ["proto", "site", "exit", "reason"]:
          usage(argv)
        else:
          self.sortby = a
      elif o == '-s' or o == '--statuscode':
        try:
          self.statuscode = int(a)
        except ValueError:
          self.statuscode = RESULT_CODES[a]

def send_mail(fro, to, subject, text, files=[]):
  assert type(to)==list
  assert type(files)==list

  msg = MIMEMultipart()
  msg['From'] = fro
  msg['To'] = COMMASPACE.join(to)
  msg['Date'] = formatdate(localtime=True)
  msg['Subject'] = subject

  msg.attach( MIMEText(text) )

  for f in files:
    part = MIMEBase('application', "octet-stream")
    part.set_payload( open(f,"rb").read() )
    Encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="%s"'
                   % os.path.basename(f))
    msg.attach(part)

  if mail_auth and not (mail_tls or mail_starttls):
    print "You've requested authentication but have not set"
    print "mail_tls or mail_starttls to True. As a friend,"
    print "I just can't let you do that to yourself."
    return

  try:
    if mail_tls:
      if sys.version_info >= (2, 6):
        smtp = smtplib.SMTP_SSL(host=mail_server)
      else:
        print "mail_tls requires Python >= 2.6"
    else:
      smtp = smtplib.SMTP(host=mail_server)
    if mail_starttls:
      smtp.starttls()
    if mail_auth:
      passwd = mail_password or getpass.getpass()
      smtp.login(mail_user, passwd)
    smtp.sendmail(fro, to, msg.as_string() )
    smtp.close()
  except smtplib.SMTPException, e:
    print e

def main(argv):
  now = time.time()
  conf=SIConf(argv)
  dh = DataHandler(conf.use_dir)

  if conf.use_file:
    results = [dh.getResult(conf.use_file)]
  elif conf.node:
    results = dh.filterByNode(dh.getAll(), conf.node)
  else:
    results = dh.getAll()

  if conf.sortby == "url":
    results.sort(lambda x, y: cmp(x.site, y.site))
  elif conf.sortby == "reason":
    results.sort(lambda x, y: cmp(x.reason, y.reason))
  elif conf.sortby == "exit":
    results.sort(lambda x, y: cmp(x.exit_node, y.exit_node))

  by_reason = {}

  for r in results:
    r.verbose = conf.verbose
    if r.reason in conf.noreasons: continue
    if conf.reasons and r.reason not in conf.reasons: continue
    if r.timestamp < conf.after or conf.before < r.timestamp: continue
    if conf.finished:
      if not r.finish_timestamp: continue
      if r.finish_timestamp < conf.finishedafter: continue
      if conf.finishedbefore < r.finish_timestamp: continue
    if (conf.falsepositives) ^ r.false_positive: continue

    # XXX: r.confirmed is not used. The variable to use here is r.from_rescan.
    # We should fix this in libsoat.py and soat.py someday.
    if conf.confirmed != r.from_rescan: continue
    if conf.confirmed:
      if conf.cron_interval and r.finish_timestamp < now-conf.cron_interval-60:
        continue
    else:
      if conf.cron_interval and r.timestamp < now-conf.cron_interval-60:
        continue
    # Don't display sites that either do not have enough tests
    # or have resulted in too many positive results.
    if r.site_result_rate[1] != 0 and \
        conf.siterate < (100.0*r.site_result_rate[0])/r.site_result_rate[1]:
      continue
    if r.exit_result_rate[1] != 0 and \
          conf.exitrate > (100.0*r.exit_result_rate[0])/r.exit_result_rate[1]:
      continue
    if (not conf.statuscode or r.status == conf.statuscode) and \
       (not conf.proto or r.proto == conf.proto) and \
       (not conf.resultfilter or r.__class__.__name__ == conf.resultfilter):
      if conf.send_email:
        by_reason.setdefault(r.reason, []).append(r)
        continue
      try:
        print r
      except KeyboardInterrupt:
        raise KeyboardInterrupt
      except (Exception, IOError), e:
        traceback.print_exc()
        sys.stderr.write("\n-----------------------------\n")
      else:
          print "\n-----------------------------\n"

  if conf.send_email:
    for rsn in by_reason.iterkeys():
      for r in by_reason[rsn]:
        print "Mailing result..."
        subject = rsn+" on "+socket.inet_ntoa(struct.pack(">I",r.exit_ip))+" ("+r.exit_name+")"
        text = ""
        try:
          text += str(r)
          text += "\n# torrc:\n"
          text += "authdirbadexit "+socket.inet_ntoa(struct.pack(">I",r.exit_ip))+" # "+r.exit_name+"\n"
          text += "\n# approved-routers\n"
          text += "!badexit "+r.exit_node+" # "+r.exit_name+"\n"
          text += "\n------------------------------------------\n"
        except Exception, e:
          text += traceback.format_exc()
        # TODO: Attach files? Or is that too much.. Maybe serve
        # them via http and include links?
        send_mail(mail_from_email, mail_to_email, subject, text)

if __name__ == "__main__":
  main(sys.argv)
