#!/bin/sh

SCANNER_DIR=~/code/tor/torflow/NetworkScanners/BwAuthority

TIMESTAMP=`date +%Y%m%d-%H%M`
ARCHIVE=$SCANNER_DIR/data/bwscan.${TIMESTAMP}
OUTPUT=$SCANNER_DIR/bwscan.V3BandwidthsFile

cd $SCANNER_DIR # Needed for import to work properly.
$SCANNER_DIR/aggregate.py $SCANNER_DIR/data $OUTPUT

if [ $? = 0 ]
then
 cp $OUTPUT $ARCHIVE
 #scp $OUTPUT bwscan@torauthority.org:/var/lib/tor.scans/bwscan > /dev/null
fi
