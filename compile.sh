#!/usr/bin/env bash

# Work on where the script on
cd $(dirname $0)

[ ! -d "build/" ] && mkdir build
cd build/ && rm -rf *
cmake .. && make -j4
