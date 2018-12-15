//
// Created by qintairan on 18-12-8.
//

#include "callback.h"

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *server = (socks5::server *)watcher->data;

    while(true) {
        struct sockaddr_in addr {};
        socklen_t len = sizeof(struct sockaddr_in);
        int client_fd = accept(fd, (struct sockaddr*)&addr, &len);
        std::cout << addr.sin_family << std::endl;
        if (client_fd == -1) {
            if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
                std::cout << "accept error: "<< errno << std::endl;
            }
            break;
        }

        auto *conn = new socks5::conn();
        conn->loop = loop;
        conn->server = server;
        conn->client.fd = fd;
        ev_io_init(conn->client.rw, client_recv_cb, client_fd, EV_READ);
//        ev_io_init(conn->client.ww, client_send_cb, client_fd, EV_WRITE);

        ev_io_start(loop, conn->client.rw);

        char ip[256];
        inet_ntop(addr.sin_family, &addr.sin_addr.s_addr, ip, sizeof(ip));
        std::cout << "host: " << ip << "   "
                  << "port: " << ntohs(addr.sin_port) << std::endl;
    }
}


void client_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {

}