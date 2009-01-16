#!/bin/sh

mkdir slices

./buildtimes.py -n 10000 -s 3 -e 80 -d ./slices >& ./slices/bt-slices.log

# Check all slices
for f in ./slices/*.nodes
do
  base = `basename ${f} .nodes`
  ./dist_check.py -f ${base} >& ${base}.check
  mv ${f} ${f}.checked
done

./buildtimes.py -n 10000 -s 3 -g -e 50 -d ./slices >& ./slices/bt-guards.log

# Check all slices
for f in ./slices/*.nodes
do
  base = `basename ${f} .nodes`
  ./dist_check.py -f $base >& ${base}.check
  mv ${f} ${f}.checked
done

./buildtimes.py -n 20000 -d slices/ -s 80 >& ./slices/bt-all.log

# Check all slices
for f in ./slices/*.nodes
do
  base = `basename ${f} .nodes`
  ./dist_check.py -f ${base} >& ${base}.check
  mv ${f} ${f}.checked
done

mv slices slices-`date +%Y-%m-%d-%H:%M`
