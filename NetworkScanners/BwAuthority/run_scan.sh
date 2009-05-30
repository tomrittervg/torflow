#!/bin/bash

# This tor must have the w status line fix as well as the stream bw fix
# Ie: 
#      git remote add mikeperry git://git.torproject.org/~mikeperry/git/tor
#      git fetch mikeperry
#      git branch --track control-ns-wfix mikeperry/control-ns-wfix
#      git checkout control-ns-wfix
TOR_EXE=../../../tor.git/src/or/tor

for i in scanner.*
do
  rm $i/scan-data/*
done

$TOR_EXE -f ./scanner.1/torrc & 
$TOR_EXE -f ./scanner.2/torrc & 
$TOR_EXE -f ./scanner.3/torrc & 

./bwauthority.py ./scanner.1/bwauthority.cfg >& ./scanner.1/bw.log &
./bwauthority.py ./scanner.2/bwauthority.cfg >& ./scanner.2/bw.log &
./bwauthority.py ./scanner.3/bwauthority.cfg >& ./scanner.3/bw.log &


