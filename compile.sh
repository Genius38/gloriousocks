#!/usr/bin/env bash

# Work on where the script on
cd $(dirname $0)

[ ! -d "build/" ] && mkdir build
cd build/ && rm -rf *
cmake .. && make -j4

# TEST
# curl --socks5 localhost:15593 -U cricetinae:123456 www.google.com