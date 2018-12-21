//
// Created by qintairan on 18-12-21.
//

#ifndef GLORIOUSOCKS_IO_H
#define GLORIOUSOCKS_IO_H


#include "utils.h"
#include "socks5.h"

#include <cstdlib>

namespace io {

    // 从 fd 中读至 buffer
    void readFromFD(struct ev_loop *loop, struct ev_io *watcher,
                    int fd, std::string& input, bool stop_watcher=false);

    // 从 buffer 中写至 fd
    void writeToFD(struct ev_loop *loop, struct ev_io *watcher,
                   int fd, std::string& output, bool stop_watcher=false);

}


#endif //GLORIOUSOCKS_IO_H
