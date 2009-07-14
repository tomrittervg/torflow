#!/bin/bash

# This tor must have the w status line fix as well as the stream bw fix
# Ie: 
#      git remote add mikeperry git://git.torproject.org/~mikeperry/git/tor
#      git fetch mikeperry
#      git branch --track rs-format-fix7 mikeperry/rs-format-fix7
#      git checkout rs-format-fix7
TOR_EXE=../../../tor.git/src/or/tor
PYTHONPATH=../../../SQLAlchemy-0.5.5/lib:../../../Elixir-0.6.1/

# NOTE: You may want to remove this line if these are not the only
# tors run by this user:
killall bwauthority.py
killall tor && sleep 5 && killall -9 tor

for i in data/scanner.*
do
  rm $i/scan-data/*
done

$TOR_EXE -f ./data/scanner.1/torrc & 
$TOR_EXE -f ./data/scanner.2/torrc & 
$TOR_EXE -f ./data/scanner.3/torrc & 
$TOR_EXE -f ./data/scanner.4/torrc & 

# If this is a fresh start, we should allow the tors time to download
# new descriptors.
sleep 60

export PYTHONPATH

nice -n 20 ./bwauthority.py ./data/scanner.1/bwauthority.cfg >& ./data/scanner.1/bw.log &
nice -n 20 ./bwauthority.py ./data/scanner.2/bwauthority.cfg >& ./data/scanner.2/bw.log &
nice -n 20 ./bwauthority.py ./data/scanner.3/bwauthority.cfg >& ./data/scanner.3/bw.log &
nice -n 20 ./bwauthority.py ./data/scanner.4/bwauthority.cfg >& ./data/scanner.4/bw.log &


