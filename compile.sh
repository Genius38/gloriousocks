#!/usr/bin/env bash

# Work on where the script on
cd $(dirname $0)
PROJECT_ROOT=`pwd`

echo "ThridParty Make"
[ ! -d "thirdparty/libev" ] && echo "No libev, please use --recursive to clone." && exit 1
[ ! -d "thirdparty/libev/build" ] && mkdir thirdparty/libev/build
cd $PROJECT_ROOT/thirdparty/libev
./configure -prefix=$PROJECT_ROOT/thirdparty/libev/build
make -j4 && make install

echo "Gloriousocks Make"
cd $PROJECT_ROOT
[ ! -d "build/" ] && mkdir build
cd build/ && rm -rf *
cmake .. && make -j4

# TEST
# curl --socks5 localhost:15593 -U cricetinae:123456 www.google.com