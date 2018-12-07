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

const int PORT_NO = 3033;

// 总连接数
int total_clients = 0;

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

void stop_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);


int main() {
    struct ev_loop *loop = ev_default_loop(0);

/* ----Stop---- */
    ev_io stop_watcher;
    ev_io_init (&stop_watcher, stop_cb, /*STDIN_FILENO*/ 0, EV_READ);
    ev_io_start (loop, &stop_watcher);
/* ------------ */

    int sd;
    struct sockaddr_in addr;
    int addr_len = sizeof(addr);
    struct ev_io w_accept;

// Create server socket
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        return -1;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_NO);
    addr.sin_addr.s_addr = INADDR_ANY;

// Bind socket to address
    if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        perror("bind error");
    }

// Start listing on the socket
    if (listen(sd, 2) < 0) {
        perror("listen error");
        return -1;
    }

// Initialize and start a watcher to accepts client requests
    ev_io_init(&w_accept, accept_cb, sd, EV_READ);
    ev_io_start(loop, &w_accept);

// Start infinite loop
    ev_run(loop, 0);
    return 0;
}

/* Accept client requests */
void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_sd;
    auto *w_client = (struct ev_io *) malloc(sizeof(struct ev_io));

    if (EV_ERROR & revents) {
        perror("got invalid event");
        return;
    }

// Accept client request
    client_sd = accept(watcher->fd, (struct sockaddr *) &client_addr, &client_len);

    if (client_sd < 0) {
        perror("accept error");
        return;
    }

    total_clients++; // Increment total_clients count
    printf("Successfully connected with client.\n");
    printf("%d client(s) connected.\n", total_clients);

// Initialize and start watcher to read client requests
    ev_io_init(w_client, read_cb, client_sd, EV_READ);
    ev_io_start(loop, w_client);
}

/* Read client message */
void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    std::string buffer;
    ssize_t read;

    if (EV_ERROR & revents) {
        perror("got invalid event");
        return;
    }

// Receive message from client socket
    read = recv(watcher->fd, &buffer[0], buffer.length(), 0);

    if (read < 0) {
        perror("read error");
        return;
    }

    if (read == 0) {
        // Stop and free watchet if client socket is closing
        ev_io_stop(loop, watcher);
        free(watcher);
        perror("peer might closing");
        total_clients--; // Decrement total_clients count
        printf("%d client(s) connected.\n", total_clients);
        return;
    }
    else {
        std::cout << "message: " << buffer << std::endl;
    }
// Send message bach to the client
    send(watcher->fd, &buffer[0], static_cast<size_t>(read), 0);
    bzero(&buffer[0], static_cast<size_t>(read));
}


/* 输入停止服务器 */
void stop_cb (struct ev_loop *loop, struct ev_io *watcher, int revents) {
    std::cout << "Server Stopped." << std::endl;
    // for one-shot events, one must manually stop the watcher
    // with its corresponding stop function.
    ev_io_stop (loop, watcher);

    // this causes all nested ev_run's to stop iterating
    ev_break (loop, EVBREAK_ALL);
}