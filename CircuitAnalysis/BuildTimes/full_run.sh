#!/bin/sh
./buildtimes.py -n 20000 -d slices/ -s 80 >& bt.log &
./buildtimes.py -n 10000 -s 3 -g -e 50 -d ./slices >& bt.log &
./buildtimes.py -n 10000 -s 3 -e 80 -d ./slices >& bt.log &

