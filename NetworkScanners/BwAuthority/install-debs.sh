#!/bin/bash

if [ ! $(dpkg -s python2.6 python2.6-dev 2>/dev/null >/dev/null) ]
then
  echo "We need python2.6 to be in the path. Press enter to try to install it."
  echo "or control-c and find your own way to install it and re-run this script"
  echo
  echo -n "Hit enter to install python2.6: "
  read
  sudo apt-get install python2.6 python2.6-dev
  if [ $? -ne 0 ]
  then
    echo
    echo "Your distribution does not natively provide python2.6."
    echo "Press enter to try to install from a ppa, or control-c to install on your own"
    echo
    echo -n "Hit enter to install from ppa:fkrull/deadsnakes: "
    read
    sudo apt-get install software-properties-common
    sudo add-apt-repository ppa:fkrull/deadsnakes
    sudo apt-get update
    sudo apt-get install python2.6 python2.6-dev
  fi
fi

sudo apt-get install libsqlite3-dev python-virtualenv
sudo apt-get install autoconf2.13 automake make libevent-dev
