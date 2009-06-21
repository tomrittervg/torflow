#!/bin/sh
TIMESTAMP=`date +%Y%m%d-%H%M`
SCANNER_DIR=~/code/torflow-trunk/NetworkScanners/BwAuthority
TOR_DEST=$SCANNER_DIR/bwscan.V3BandwidthsFile
OUTPUT=$SCANNER_DIR/data/bwscan.${TIMESTAMP}

cd $SCANNER_DIR # Needed for import to work properly.
$SCANNER_DIR/aggregate.py $SCANNER_DIR/data $OUTPUT

cp $OUTPUT $TOR_DEST
#scp $OUTPUT tor@authority.org:/var/lib/tor/V3Bandwidths 

