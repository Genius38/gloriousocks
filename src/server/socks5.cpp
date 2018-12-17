//
// Created by qintairan on 18-12-7.
//

#include "socks5.h"

socks5::conn::conn() {
    // To Keep status
    this->client.rw = new ev_io();
    this->client.rw->data = this;

    this->client.ww = new ev_io();
    this->client.ww->data = this;

    this->remote.rw = new ev_io();
    this->remote.rw->data = this;

    this->remote.ww = new ev_io();
    this->remote.ww->data = this;

    this->stage = socks5::STATUS_NEGO_METHODS;
}

socks5::conn::~conn() {
    // Close fd and stop supervisor
    if (this->client.fd > 0) {
        ev_io_stop(loop, this->client.rw);
        ev_io_stop(loop, this->client.ww);
        close(this->client.fd);
    }

    if (this->remote.fd > 0) {
        ev_io_stop(loop, this->remote.rw);
        ev_io_stop(loop, this->remote.ww);
        close(this->remote.fd);
    }
}
