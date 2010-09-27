#!/bin/bash

SCANDIR=~/code/torflow.git/NetworkScanners/ExitAuthority/

$SCANDIR/snakeinspector.py --confirmed --email --noreason FailureTimeout --croninterval 24 --siterate 3

# Optionally, you can use these two lines to allow less regular cron
# scheduling:

#$SCANDIR/snakeinspector.py --confirmed --email --noreason FailureTimeout --siterate 3 --finishedafter "`cat $SCANDIR/lastmail.time`"
#date +"%a %b %d %H:%M:%S %Y" > $SCANDIR/lastmail.time
