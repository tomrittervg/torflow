#!/bin/sh
SCANNER_DIR=~/code/torflow-trunk/NetworkScanners/BwAuthority
TOR_DEST=$SCANNER_DIR/bwscan.V3BandwidthsFile

cd $SCANNER_DIR # Needed for import to work properly.
$SCANNER_DIR/aggregate.py $SCANNER_DIR/data $SCANNER_DIR/data/bwscan.all

cp $SCANNER_DIR/data/bwscan.all $TOR_DEST
#scp $SCANNER_DIR/data/bwscan.all tor@authority.org:/var/lib/tor/V3Bandwidths 

