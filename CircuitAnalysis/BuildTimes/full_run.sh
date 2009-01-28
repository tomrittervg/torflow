#!/bin/sh

mkdir slices

./buildtimes.py -n 10000 -s 3 -e 93 -c 15 -d ./slices >& ./slices/bt-slices.log
./buildtimes.py -n 10000 -s 3 -g -e 50 -c 30 -d ./slices >& ./slices/bt-guards.log
./buildtimes.py -n 100000 -d slices/ -s 93 -c 100 >& ./slices/bt-all.log

mv slices slices-`date +%Y-%m-%d-%H:%M`
