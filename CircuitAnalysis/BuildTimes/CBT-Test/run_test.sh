#!/bin/sh
# TODO:
# 1. Fire up a Tor
# 2. For every 5% percentile, loop N times:
# 3.   Remove state file + hup tor.
# 4.   Run test with 3 guards from a percentile for c>10 circuits:
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

TOR_DIR=../../tor.git/src/or
TOR_DATA=./tor-data/

kill `cat $TOR_DATA/tor.pid`
if [ $? -eq 0 ]
then
 sleep 10
fi

$TOR_DIR/tor -f $TOR_DATA/torrc

# XXX: Handle no guards left case
for p in 65 0 5 10 15 20 25 30 35 40 45 50 55 60
do
  rm $TOR_DATA/state
  kill -HUP `cat $TOR_DATA/tor.pid`
  N=0
  while [ $N -lt 10 ]
  do
    mkdir -p results/$p/$N/min
    mkdir -p results/$p/$N/full
    echo ./cbt-test.py -m -P 5 -p $p -o results/$p/$N/min/result -b results/$p/$N/min/buildtimes
    # XXX: check retval
    cp $TOR_DATA/state results/$p/$N/min/state
    echo ./cbt-test.py -f -P 5 -p $p -o results/$p/$N/full/result -b results/$p/$N/full/buildtimes 
    cp $TOR_DATA/state results/$p/$N/full/state
    N=`expr $N + 1`
  done
done

for p in `ls -1 results`
do
  for n in `ls -1 results/$p`
  do
    for t in `ls -1 results/$p/$n`
    do
      M=0
      while [ $M -lt 3 ]
      do
        cp results/$p/$n/$t $TOR_DATA/state
        kill -HUP `cat $TOR_DATA/tor.pid`
        echo ./cbt-test.py -r -o results/$p/$n/$t/result -b results/$p/$N/buildtimes.redo.$M
        M=`expr $N + 1`
      done
    done
  done
done

