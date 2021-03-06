#!/bin/sh

# Number of applications to run.
SCANNERS_PER_TOR_COUNT=4
TOR_COUNT=2
SCANNER_COUNT=$(($SCANNERS_PER_TOR_COUNT * $TOR_COUNT + 1))

# This tor must have the w status line fix as well as the stream bw fix
# Ie git master or 0.2.2.x
TOR_EXE=../../../tor/src/or/tor
PYTHONPATH=../../../SQLAlchemy-0.7.10/lib:../../../Elixir-0.7.1/

! [ -e "./local.cfg" ] || . "./local.cfg"

for n in `seq $SCANNER_COUNT`; do
  PIDFILE=./data/scanner.${n}/bwauthority.pid
  if [ -f $PIDFILE ]; then
    echo "Killing off scanner $n."
    kill -9 `head -1 $PIDFILE` && rm $PIDFILE
  fi
done

KILLED_TOR=false
for n in `seq $TOR_COUNT`; do
  PIDFILE=./data/tor.${n}/tor.pid
  if [ -f $PIDFILE ]; then
    if kill -0 `head -1 $PIDFILE` 2>/dev/null; then # it is a running process and we may send signals to it
  	  kill `head -1 $PIDFILE`
  	  if [ $? -eq 0 ]; then
  	    KILLED_TOR=true
  	  fi
    fi
  fi
done

sleep 5

# FIXME: We resume in a ghetto way by saving the bws-*done* files.
# A more accurate resume could be implemented in bwauthority.py
find data/scanner.* -name .svn -prune -o -type f -a ! -name '*-done-*' -a ! -name bwauthority.cfg -a ! -name .gitignore -exec rm {} +

for n in `seq $TOR_COUNT`; do
	rm -f ./data/tor.${n}/tor.log
	$TOR_EXE -f ./data/tor.${n}/torrc &
done

# If this is a fresh start, we should allow the tors time to download
# new descriptors.
if [ $KILLED_TOR ]; then
  echo "Waiting for 60 seconds to refresh tors..."
  sleep 60
else
  echo "We did not kill any Tor processes from any previous runs.. Waiting for 500s to fetch full consensus.."
  sleep 500
fi

if [ -f bwauthenv/bin/activate ]
then
  echo "Using virtualenv in bwauthenv..."
  . bwauthenv/bin/activate
fi

[ -z "$PYTHONPATH" ] || export PYTHONPATH
for n in `seq $SCANNER_COUNT`; do
    nice -n 20 ./bwauthority.py ./data/scanner.${n}/bwauthority.cfg \
         > ./data/scanner.${n}/bw.log 2>&1 &
done

echo "Launched $SCANNER_COUNT bandwidth scanners. Job listing: "
jobs -l
