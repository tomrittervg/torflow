#!/bin/bash

# This tor must have the w status line fix as well as the stream bw fix
# Ie: 
#      git remote add mikeperry git://git.torproject.org/~mikeperry/git/tor
#      git fetch mikeperry
#      git branch --track rs-format-fix7 mikeperry/rs-format-fix7
#      git checkout rs-format-fix7
TOR_EXE=../../../tor.git/src/or/tor
PYTHONPATH=../../../SQLAlchemy-0.5.5/lib:../../../Elixir-0.6.1/

killall bwauthority.py

KILLED_TOR=false

for i in data/scanner.*
do
  if [ -f "$i/tor.pid" ]; then
    PID=`cat $i/tor.pid`
    kill $PID
    if [ $? -eq 0 ]; then
      KILLED_TOR=true
    fi
  fi
done

sleep 5

# FIXME: We resume in a ghetto way by saving the bws-*done* files.
# A more accurate resume could be implemented in bwauthority.py
for i in data/scanner.*
do
  find $i/scan-data/ -depth -type f -print | egrep -v -- "-done-|\/.svn" | xargs -P 1024 rm
  #rm $i/scan-data/*
done

$TOR_EXE -f ./data/scanner.1/torrc & 
$TOR_EXE -f ./data/scanner.2/torrc & 
$TOR_EXE -f ./data/scanner.3/torrc & 
$TOR_EXE -f ./data/scanner.4/torrc & 

# If this is a fresh start, we should allow the tors time to download
# new descriptors.
if [ $KILLED_TOR ]; then
  echo "Waiting for 60 seconds to refresh tors..."
  sleep 60
else
  echo "We did not kill any Tor processes from any previous runs.. Waiting for
5 min to fetch full consensus.."
  sleep 300
fi

export PYTHONPATH

nice -n 20 ./bwauthority.py ./data/scanner.1/bwauthority.cfg >& ./data/scanner.1/bw.log &
nice -n 20 ./bwauthority.py ./data/scanner.2/bwauthority.cfg >& ./data/scanner.2/bw.log &
nice -n 20 ./bwauthority.py ./data/scanner.3/bwauthority.cfg >& ./data/scanner.3/bw.log &
nice -n 20 ./bwauthority.py ./data/scanner.4/bwauthority.cfg >& ./data/scanner.4/bw.log &


