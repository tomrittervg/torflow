#!/usr/bin/env python
from sys import argv as s_argv
from sys import path
from sys import exit
from subprocess import Popen
path.append("../../")
import TorCtl.TorUtil
from TorCtl.TorUtil import plog as plog
from TorCtl.TorUtil import get_git_version as get_git_version
from signal import signal, SIGTERM, SIGKILL


# exit code to indicate scan completion
# make sure to update this in bwauthority_child.py as well
STOP_PCT_REACHED = 9
RESTART_SLICE = 1

# path to git repos (.git)
PATH_TO_TORFLOW_REPO = '../../.git/'
PATH_TO_TORCTL_REPO = '../../.git/modules/TorCtl/'

p = None

def main(argv):
  TorCtl.TorUtil.read_config(argv[1])
  (branch, head) = get_git_version(PATH_TO_TORFLOW_REPO)
  plog('NOTICE', 'TorFlow Version: %s' % branch+' '+head)
  (branch, head) = get_git_version(PATH_TO_TORCTL_REPO)
  plog('NOTICE', 'TorCtl Version: %s' % branch+' '+head)
  slice_num = 0 
  while True:
    plog('INFO', 'Beginning time loop')
    global p
    p = Popen(["python", "bwauthority_child.py", argv[1], str(slice_num)])
    p.wait()
    if (p.returncode == 0):
      slice_num += 1
    elif (p.returncode == RESTART_SLICE):
      plog('NOTICE', 'restarting slice_num '+str(slice_num))
    elif (p.returncode == STOP_PCT_REACHED):
      plog('NOTICE', 'restarting from slice 0')
      slice_num = 0
    elif (abs(p.returncode) == SIGKILL):
      plog('WARN', 'Child process recieved SIGKILL, exiting')
      exit()
    elif (abs(p.returncode) == SIGTERM):
      #XXX
      # see: https://trac.torproject.org/projects/tor/ticket/3701
      # if uncaught exceptions are raised in user-written handlers, TorCtl
      # will kill the bwauthority_child process using os.kill() because sys.exit()
      # only exits the thread in which the exception is caught.
      # quote mikeperry: "we want this thing not do die. that is priority one"
      # therefore: we restart the child process and hope for the best :-)
      plog('WARN', 'Child process recieved SIGTERM')
      #exit()

    else:
      plog('WARN', 'Child process returned %s' % p.returncode)

def sigterm_handler(signum, frame):
  global p
  if p:
    p.kill()
  exit()

if __name__ == '__main__':
  signal(SIGTERM, sigterm_handler)
  try:
    main(s_argv)
  except KeyboardInterrupt:
    global p
    p.kill()
    plog('NOTICE', "Ctrl + C was pressed. Exiting ... ")
  except Exception as e:
    plog('ERROR', "An unexpected error occured: "+str(e))
