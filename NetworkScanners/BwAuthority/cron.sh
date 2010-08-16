#!/bin/sh

SCANNER_DIR=~/code/tor/torflow/NetworkScanners/BwAuthority

TIMESTAMP=`date +%Y%m%d-%H%M`
TOR_DEST=$SCANNER_DIR/bwscan.V3BandwidthsFile
OUTPUT=$SCANNER_DIR/data/bwscan.${TIMESTAMP}

cd $SCANNER_DIR # Needed for import to work properly.
$SCANNER_DIR/aggregate.py $SCANNER_DIR/data $OUTPUT

if [ $? = 0 ]
then
 cp $OUTPUT $TOR_DEST
 #scp $TOR_DEST bwscan@torauthority.org:/var/lib/tor.scans/bwscan > /dev/null
fi
