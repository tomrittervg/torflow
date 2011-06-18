#!/usr/bin/env python
import sys
import subprocess
import ConfigParser
import os
import traceback
sys.path.append("../../")
from TorCtl import TorUtil
from TorCtl.TorUtil import plog


# exit code to indicate scan completion
# make sure to update this in bwauthority_child.py as well
STOP_PCT_REACHED = -9

def main(argv):
  slice_num = 0 
  while True:
    plog('INFO', 'Beginning time loop')
    global p
    p = subprocess.Popen(["python", "bwauthority_child.py", argv[1], str(slice_num)])
    p.wait()
    if (p.returncode == 0):
      slice_num += 1
    elif (p.returncode == STOP_PCT_REACHED):
      plog('INFO', 'restarting from slice 0')
      slice_num = 0
    else:
      plog('WARN', 'Child process returned %s' % p.returncode)

if __name__ == '__main__':
  try:
    main(sys.argv)
  except KeyboardInterrupt:
    p.kill()
    plog('INFO', "Ctrl + C was pressed. Exiting ... ")
    traceback.print_exc()
  except Exception, e:
    plog('ERROR', "An unexpected error occured.")
    traceback.print_exc()
