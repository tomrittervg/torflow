#!/bin/sh

mkdir slices

./buildtimes.py -n 10000 -s 3 -e 80 -d ./slices >& ./slices/bt-slices.log
./buildtimes.py -n 10000 -s 3 -g -e 50 -d ./slices >& ./slices/bt-guards.log
./buildtimes.py -n 20000 -d slices/ -s 80 >& ./slices/bt-all.log

mv slices slices-`date +%Y-%m-%d-%H:%M`
