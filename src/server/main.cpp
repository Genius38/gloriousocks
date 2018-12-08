//
// Created by qintairan on 18-12-7.
//

#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <string>
#include "socks5.hpp"
#include <netinet/in.h>
#include <ev.h>

int main(int argc, char **argv) {
    struct ev_loop *loop = ev_default_loop(0);
    struct ev_io server_watcher;

}