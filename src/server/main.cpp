//
// Created by qintairan on 18-12-7.
//

#include <cstdlib>
#include <cstdio>

#include <iostream>
#include <string>

#include <netinet/in.h>
#include <ev.h>
#include <unistd.h>

#include "callback.h"


/* Proxy server 屬性 */
static socks5::server g_server = {
    /*.ulen=*/          10,
    /*.username=*/      "cricetinae",
    /*.plen=*/          6,
    /*.password=*/      "123456",
    /*.port=*/          15593,
    /*.auth_method=*/   socks5::METHOD_USERNAMEPASSWORD,
};


int main(int argc, char **argv) {
    struct ev_loop *loop = ev_default_loop(0);
    struct ev_io server_watcher;

    // socket fd
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cout << "sock fd error" << std:: endl;
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr {};
    memset((char *)&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(uint16_t(g_server.port));
    addr.sin_addr.s_addr = INADDR_ANY;

    // 设置nonblocking
    if (utils::setSocketNonBlocking(fd) < 0) {
        close(fd);
        return EXIT_FAILURE;
    }

    // 设置reuseaddr
    if(utils::setSocketReuseAddr(fd) < 0) {
        close(fd);
        return EXIT_FAILURE;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        std::cout << "bind error:" << errno << std::endl;
        close(fd);
        return EXIT_FAILURE;
    }

    if (listen(fd, 128) < 0) {
        std::cout << "listen error:" << errno << std::endl;
        close(fd);
        return EXIT_FAILURE;
    }

    server_watcher.fd = fd;
    server_watcher.data = &g_server;   // Key, 夾帶數據內容傳入cb

    ev_io_init(&server_watcher, accept_cb, server_watcher.fd, EV_READ);
    ev_io_start(loop, &server_watcher);

    std::cout            << "[Socks5]"
    "   Server Start. "  <<
    "   port: "          << g_server.port                    <<
    "   auth_method:  "  << to_string(g_server.auth_method)  << std::endl;

    ev_run(loop, 0);

    return EXIT_SUCCESS;
}