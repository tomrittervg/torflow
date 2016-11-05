#!/bin/bash -e

SCANNER_DIR=$(dirname "$0")
SCANNER_DIR=$(readlink -f "$SCANNER_DIR")

PYTHON=$(which python2.6 || which python2.7)

# 1. Install python if needed
if [ -z "$(which $PYTHON)" ]
then
  echo "We need python2.6 or 2.7 to be in the path."
  echo "If you are on a Debian or Ubuntu system, you can try: "
  echo " sudo apt-get install python2.7 python2.7-dev libpython2.7-dev libsqlite3-dev python-virtualenv autoconf2.13 automake make libevent-dev"
  exit 1
fi

if [ -z "$(which virtualenv)" ]
then
  echo "We need virtualenv to be in the path. If you are on a debian system, try:"
  echo " sudo apt-get install python-dev libsqlite3-dev python-virtualenv autoconf2.13 automake make libevent-dev"
  exit 1
fi

# 2. Ensure TorCtl submodule is added
pushd ../../
./add_torctl.sh
popd

# 3. Compile tor 0.2.8
if [ ! -x ../../../tor/src/or/tor ]
then
  pushd ../../../
  git clone https://git.torproject.org/tor.git tor
  cd tor
  git checkout release-0.2.8
  ./autogen.sh
  ./configure --disable-asciidoc
  make -j4
  popd
fi

# 4. Initialize virtualenv
if [ ! -f bwauthenv/bin/activate ]
then
  virtualenv -p $PYTHON bwauthenv
fi
source bwauthenv/bin/activate

# 5. Install new pip and peep
pip install --upgrade https://pypi.python.org/packages/source/p/pip/pip-6.1.1.tar.gz#sha256=89f3b626d225e08e7f20d85044afa40f612eb3284484169813dc2d0631f2a556
pip install https://pypi.python.org/packages/source/p/peep/peep-2.4.1.tar.gz#sha256=2a804ce07f59cf55ad545bb2e16312c11364b94d3f9386d6e12145b2e38e5c1c
peep install -r $SCANNER_DIR/requirements.txt

# 6. Prepare cron script
cp cron.sh cron-mine.sh
echo -e "45 0-23 * * * $SCANNER_DIR/cron-mine.sh" | crontab
echo -e "@reboot $SCANNER_DIR/run_scan.sh\n`crontab -l`" | crontab
echo "Prepared crontab. Current crontab: "
crontab -l

# 7. Inform user what to do
echo
echo "If we got this far, everything should be ready!"
echo
echo "Start the scan with ./run_scan.sh"
echo "You can manually run ./cron-mine.sh manually to check results"
echo "Detailed logs are in ./data/scanner.*/bw.log."
echo "Progress can also be inferred from files in ./data/scanner.*/scan-data"
