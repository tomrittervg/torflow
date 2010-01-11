#!/bin/sh
# TODO:
# 1. Fire up a Tor
# 2. For every 5% percentile, loop N times:
# 3.   Remove state file + hup tor.
# 4.   Run test with 3 guards from a percentile for c>50 circuits:
# 5.     Record MIN_CIRCS=c/2 when past c/2 circuits did not change
#        timeout more than +/-1.
# 6.       Copy state file to saved location w/ guards and c/2
# 7.     Stop test when past NCIRCS=c/2 circuits did not change timeout
# 8.       Copy state file to new location w/ guards and c/2
# 9. For each state file:
# 10.   Insert state file + hup tor.
# 11.   Loop M times for chosen guards:
# 12.     Build NCIRCS circuits
# 13.     Record circuit complete/(complete+timeout)
# 14. XXX: Determine what % +/- 1, 2, 3 seconds gives us
# 15. XXX: Graph timeout learned vs circuits over time.
#
# 4-8 in python
# 11-13 in python
#
# Pick N = 10
# Pick M = 3
#
# Final outputs:
#  Percentile, MIN_CIRCS+timeout, NCIRCS+timeout, guards
#
# To do this need:
# A. Event to export when circuitbuildtimeout is set
#    - Check.
# B. SIGNAL to close all circuits/build more?
#    -> Or just close them via metatroller.. Make sure it will keep building
#       though..
# C. SETCONF EntryNodes/StrictEntryNodes

TOR_DIR=../../../../tor.git/src/or
TOR_DATA=./tor-data/

if [ -f $TOR_DATA/tor.pid ]; then
  kill `cat $TOR_DATA/tor.pid`
  if [ $? -eq 0 ]
  then
   sleep 10
  fi
fi

for p in 0 10 # 20 30 40 50 60 70 80 90
do
  N=0
  while [ $N -lt 2 ] #10 ]
  do
    if [ -f $TOR_DATA/tor.pid ]; then
      kill `cat $TOR_DATA/tor.pid`
      wait `cat $TOR_DATA/tor.pid`
    fi
    rm $TOR_DATA/state
    $TOR_DIR/tor -f $TOR_DATA/torrc &
    sleep 10
    mkdir -p results/$p/$N
    ./cbttest.py -p $p -o results/$p/$N || exit
    N=`expr $N + 1`
  done
done

for p in `ls -1 results`
do
  for n in `ls -1 results/$p`
  do
    M=0
    while [ $M -lt 2 ] # 3 ]
    do
      if [ -f $TOR_DATA/tor.pid ]; then
        kill `cat $TOR_DATA/tor.pid`
        wait `cat $TOR_DATA/tor.pid`
      fi
      cp results/$p/$n/state.full $TOR_DATA/state
      $TOR_DIR/tor -f $TOR_DATA/torrc &
      sleep 10
      mkdir -p results/$p/$n/redo.$M
      ./cbttest.py -p $p -o results/$p/$n/redo.$M || exit
      M=`expr $N + 1`
    done
  done
done

