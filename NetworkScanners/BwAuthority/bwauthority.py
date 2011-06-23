#!/usr/bin/env python
from sys import argv as s_argv
from sys import path
from sys import exit
from subprocess import Popen
path.append("../../")
from TorCtl.TorUtil import plog as plog
from signal import signal, SIGTERM, SIGKILL


# exit code to indicate scan completion
# make sure to update this in bwauthority_child.py as well
STOP_PCT_REACHED = 9

def main(argv):
  slice_num = 0 
  while True:
    plog('INFO', 'Beginning time loop')
    global p
    p = Popen(["python", "bwauthority_child.py", argv[1], str(slice_num)])
    p.wait()
    if (p.returncode == 0):
      slice_num += 1
    elif (p.returncode == STOP_PCT_REACHED):
      plog('INFO', 'restarting from slice 0')
      slice_num = 0
    elif (abs(p.returncode) == SIGKILL):
      plog('WARN', 'Child process recieved SIGKILL, exiting')
      exit()
    elif (abs(p.returncode) == SIGTERM):
      plog('WARN', 'Child process recieved SIGTERM, exiting')
      exit()
    else:
      plog('WARN', 'Child process returned %s' % p.returncode)

def sigterm_handler(signum, frame):
  if p:
    p.kill()
  exit()

if __name__ == '__main__':
  signal(SIGTERM, sigterm_handler)
  try:
    main(s_argv)
  except KeyboardInterrupt:
    p.kill()
    plog('INFO', "Ctrl + C was pressed. Exiting ... ")
  except Exception, e:
    plog('ERROR', "An unexpected error occured.")
