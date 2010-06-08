#!/usr/bin/python

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

from libsoat import *
from soat_config_real import *

sys.path.append("../../")
import TorCtl.TorUtil

TorCtl.TorUtil.loglevel="INFO"

if TorCtl.TorUtil.loglevels[TorCtl.TorUtil.loglevel] > TorCtl.TorUtil.loglevels["INFO"]:
  # Kill stderr (jsdiffer and exception noise) if our loglevel is above INFO
  sys.stderr = file("/dev/null", "w")


def usage(argv):
  print "Usage: "+argv[0]+" with 0 or more of the following filters: "
  print "  --dir <datadir>"
  print "  --file <.result file>"
  print "  --exit <idhex>"
  print "  --before <timestamp as string>"
  print "  --after <timestamp as string>"
  print "  --reason <soat failure reason>    # may be repeated"
  print "  --noreason <soat failure reason>  # may be repeated"
  print "  --proto <protocol>"
  print "  --resultfilter <TestResult class name>"
  print "  --statuscode <'Failure' or 'Inconclusive'>"
  print "  --sortby <'proto' or 'url' or 'exit' or 'reason'>"
  print "  --falsepositives"
  print "  --verbose"
  sys.exit(1)

def getargs(argv):
  try:
    opts,args = getopt.getopt(argv[1:],"d:f:e:x:r:vt:p:s:o:n:a:b:Fmc",
             ["dir=", "file=", "exit=", "reason=", "resultfilter=", "proto=",
              "verbose", "statuscode=", "sortby=", "noreason=", "after=",
              "before=", "falsepositives", "email", "confirmed"])
  except getopt.GetoptError,err:
    print str(err)
    usage(argv)
  # FIXME: make all these repeatable
  use_dir="./data/"
  use_file=None
  node=None
  reasons=[]
  noreasons=[]
  result=2
  verbose=1
  proto=None
  resultfilter=None
  before = 0xffffffff
  after = 0
  sortby="proto"
  falsepositives=False
  send_email = False
  confirmed = False
  for o,a in opts:
    if o == '-d' or o == '--dir':
      use_dir = a
    elif o == '-e' or o == '--email':
      send_email = True
    elif o == '-x' or o == '--exit':
      node = a
    elif o == '-f' or o == '--file':
      use_file = a
    elif o == '-b' or o == '--before':
      before = time.mktime(time.strptime(a))
    elif o == '-a' or o == '--after': 
      after = time.mktime(time.strptime(a))
    elif o == '-r' or o == '--reason': 
      reasons.append(a)
    elif o == '-r' or o == '--noreason': 
      noreasons.append(a)
    elif o == '-v' or o == '--verbose': 
      verbose += 1
    elif o == '-t' or o == '--resultfilter':
      resultfilter = a
    elif o == '-p' or o == '--proto':
      proto = a
    elif o == '-F' or o == '--falsepositives':
      falsepositives = True
    elif o == '-c' or o == '--confirmed':
      confirmed = True
    elif o == '-s' or o == '--sortby': 
      if a not in ["proto", "site", "exit", "reason"]:
        usage(argv)
      else: sortby = a 
    elif o == '-s' or o == '--statuscode': 
      try:
        result = int(a)
      except ValueError:
        result = RESULT_CODES[a]
  return use_dir,use_file,node,reasons,noreasons,result,verbose,resultfilter,proto,sortby,before,after,falsepositives,send_email,confirmed

def send_mail(fro, to, subject, text, server, files=[]):
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

  smtp = smtplib.SMTP(server)
  smtp.sendmail(fro, to, msg.as_string() )
  smtp.close()


def main(argv):
  now = time.time()
  use_dir,use_file,node,reasons,noreasons,result,verbose,resultfilter,proto,sortby,before,after,falsepositives,send_email,confirmed=getargs(argv)
  dh = DataHandler(use_dir)

  if use_file:
    results = [dh.getResult(use_file)]
  elif node:
    results = dh.filterByNode(dh.getAll(), node)
  else:
    results = dh.getAll()

  if sortby == "url":
    results.sort(lambda x, y: cmp(x.site, y.site))
  elif sortby == "reason":
    results.sort(lambda x, y: cmp(x.reason, y.reason))
  elif sortby == "exit":
    results.sort(lambda x, y: cmp(x.exit_node, y.exit_node))

  by_proto = {}

  for r in results:
    r.verbose = verbose
    if r.reason in noreasons: continue
    if reasons and r.reason not in reasons: continue
    if r.timestamp < after or before < r.timestamp: continue
    if (falsepositives) ^ r.false_positive: continue
    if confirmed != r.confirmed: continue
    if (not result or r.status == result) and \
       (not proto or r.proto == proto) and \
       (not resultfilter or r.__class__.__name__ == resultfilter):
      if send_email:
        if r.timestamp > now - mail_interval - 60:
          if r.proto not in by_proto:
            by_proto[r.proto]=[]
          by_proto[r.proto].append(r)
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

  if send_email:
    for p in by_proto.iterkeys():
      print "Mailing "+str(len(by_proto[p]))+" "+p+" results..."
      subject = p+" scan found "+str(len(by_proto[p]))+" snakes"
      text = ""
      for r in by_proto[p]:
        try:
          text += str(r) + "\n-----------------------------\n"
        except Exception, e:
          text += traceback.format_exc()
      # TODO: Attach files? Or is that too much.. Maybe serve
      # them via http and include links?
      send_mail(from_email, to_email, subject, text, mail_server)

if __name__ == "__main__":
  main(sys.argv)
