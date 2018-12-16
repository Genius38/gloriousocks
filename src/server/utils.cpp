//
// Created by qintairan on 18-12-16.
//

#include "utils.h"


void utils::close_conn(socks5::conn* conn, int fd,
                const std::string& msg, bool has_errno, bool* loopable) {

    if (has_errno && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
        std::cout << msg << ", errno: " << errno << std::endl;
    }

    if (!has_errno) {
        std::cout << msg << std::endl;
    }

    if (conn) {
        delete conn;
        conn = nullptr;
    }

    if (fd > 0) {
        close(fd);
    }

    if(loopable) {
        *loopable = false;
    }
}


void utils::display_stage(socks5::conn* conn) {
    std::cout << "connection stage: [" << conn->stage << "]\n";
}


void utils::msg(const std::string& msg) {
    std::cout << msg << std::endl;
}


bool utils::setSocketNonBlocking(int fd) {
    if (fd < 0) return false;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return false;
    flags = (flags | O_NONBLOCK);
    return fcntl(fd, F_SETFL, flags) == 0;
}


int utils::setSocketReuseAddr(int fd) {
    int enable = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

}


void utils::str_concat_char(std::string& str, char* ch, const ssize_t size) {
    char message[size];
    memcpy(message, ch, size_t(size));
    str += *(new string(message));
}