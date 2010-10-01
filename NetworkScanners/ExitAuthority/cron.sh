#!/bin/bash

SCANDIR=~/code/torflow.git/NetworkScanners/ExitAuthority/

# 1. Email results to addresses in soat_config.py (--email)
# 2. Ignore timeout errors (--noreason FailureTimeout)
# 3. Schedule this script every hour (--croninterval 1).
# 4. Only report from urls that fail from less than 10% of the total
#    exits tested so far. (--siterate 10)
# 5. Only report exits that fail 100% of their tests (--exitrate 99)
$SCANDIR/snakeinspector.py --email --noreason FailureTimeout --exitrate 99 --siterate 10 --croninterval 1

# Optionally, you can use these two lines to allow less regular cron
# scheduling:

#$SCANDIR/snakeinspector.py --confirmed --email --noreason FailureTimeout --siterate 3 --finishedafter "`cat $SCANDIR/lastmail.time`"
#date +"%a %b %d %H:%M:%S %Y" > $SCANDIR/lastmail.time
