#!/bin/bash

# This tor must have the w status line fix as well as the stream bw fix
# Ie: 
#      git remote add mikeperry git://git.torproject.org/~mikeperry/git/tor
#      git fetch mikeperry
#      git branch --track rs-format-fix mikeperry/rs-format-fix
#      git checkout rs-format-fix
TOR_EXE=../../../tor.git/src/or/tor
#PYTHONPATH=../../../SQLAlchemy-0.5.4p2/lib

for i in data/scanner.*
do
  rm $i/scan-data/*
done

$TOR_EXE -f ./data/scanner.1/torrc & 
$TOR_EXE -f ./data/scanner.2/torrc & 
$TOR_EXE -f ./data/scanner.3/torrc & 

# If this is a fresh start, we should allow the tors time to download
# new descriptors.
sleep 60

export PYTHONPATH

./bwauthority.py ./data/scanner.1/bwauthority.cfg >& ./data/scanner.1/bw.log &
./bwauthority.py ./data/scanner.2/bwauthority.cfg >& ./data/scanner.2/bw.log &
./bwauthority.py ./data/scanner.3/bwauthority.cfg >& ./data/scanner.3/bw.log &


