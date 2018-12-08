//
// Created by qintairan on 18-12-7.
//

#include "socks5.hpp"

socks5::server::server() {
    this->conn_in->rw = new ev_io();
    this->conn_in->ww = new ev_io();
    this->conn_ex->rw = new ev_io();
    this->conn_ex->ww = new ev_io();
}

socks5::server::~server() {
    if (this->conn_in->sd) {
        ev_io_stop(loop, this->conn_in->rw);
        ev_io_stop(loop, this->conn_in->ww);
        close(this->conn_in->sd);
    }

    if (this->conn_ex->sd) {
        ev_io_stop(loop, this->conn_ex->rw);
        ev_io_stop(loop, this->conn_ex->ww);
        close(this->conn_ex->sd);
    }
}
