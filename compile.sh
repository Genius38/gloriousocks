#!/usr/bin/env bash

[ ! -d "build/" ] && mkdir build
cd build/ && rm -rf *
cmake .. && make -j4
