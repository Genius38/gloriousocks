//
// Created by qintairan on 18-12-8.
//

#ifndef GLORIOUSOCKS_CALLBACK_H
#define GLORIOUSOCKS_CALLBACK_H

#include <ev.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include <string>

#include "socks5.h"
#include "utils.h"

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

void client_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void client_send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

void remote_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void remote_send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

#endif //GLORIOUSOCKS_CALLBACK_H
