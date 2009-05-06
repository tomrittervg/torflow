#!/bin/sh

mkdir slices

./buildtimes.py -n 1000 -s 3 -e 93 -c 15 -q -d ./slices >& ./slices/bt-slices.log
./buildtimes.py -n 1000 -s 3 -g -e 50 -c 30 -q -d ./slices >& ./slices/bt-guards.log
./buildtimes.py -n 10000 -d slices/ -s 93 -c 100 -q >& ./slices/bt-all.log

mv slices slices-`date +%Y-%m-%d-%H:%M`
