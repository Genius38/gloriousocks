//
// Created by qintairan on 18-12-16.
//

#include "utils.h"


void utils::close_conn(socks5::conn* conn, int fd,
                const std::string& msg, bool has_errno, bool* loopable) {

    // 报错关闭
    if (has_errno && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
        std::cout << msg << ", errno: " << errno << std::endl;
        if (conn) {
            delete conn;
            conn = nullptr;
        }
        if (fd > 0) close(fd);
    }

    // 非报错直接关闭
    if (!has_errno) {
        std::cout << msg << std::endl;
        if (conn) {
            delete conn;
            conn = nullptr;
        }
        if (fd > 0) close(fd);
    }

    if(loopable) {
        *loopable = false;
    }
}


void utils::msg(const std::string& msg) {
    std::cout << msg << std::endl;
}


int utils::setSocketNonBlocking(int fd) {
    int flag = fcntl(fd, F_GETFL, 0);
    if (flag == -1) return flag;
    return fcntl(fd, F_SETFL, flag | O_NONBLOCK);
}


int utils::setSocketReuseAddr(int fd) {
    int enable = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

}


void utils::str_concat_char(std::string& str, char* ch, const ssize_t size) {
    str.resize(str.length()+size);
    memcpy(&str[str.length()-size], ch, size_t(size));
}