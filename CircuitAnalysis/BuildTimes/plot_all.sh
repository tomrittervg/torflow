#!/bin/sh

# This is really ghetto. 100% dependent on fixed paths here...

for i in ./slices/*.extendtimes
do
  R --vanilla $i < ./extend_plot.r
done

for i in ./slices/*.buildtimes
do
  ./shufflebt.py -d ./slices -g $i
done

# Did I mention it's super ghetto? 
mv ./slices/*.png ./plots/
