//
// Created by qintairan on 18-12-8.
//

#include "callback.h"

const int BUFFER_LEN = 256;     // 默認 read 長度

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *server = (socks5::server *)watcher->data;     // accept 的信息夾帶 服務器屬性

    bool loopable = true;   // 標記是否繼續循環
    std::string msg = "";
    do {
        struct sockaddr_in addr {};
        socklen_t len = sizeof(struct sockaddr_in);
        int client_fd = accept(fd, (struct sockaddr*)&addr, &len);

        if (client_fd == -1) {
            utils::close_conn(nullptr, client_fd, "accept error", true, &loopable);
        }

        if (!utils::setSocketNonBlocking(client_fd)) {
            utils::close_conn(nullptr, client_fd, "set nonblocking: ", true, &loopable);
            continue;
        }

        auto conn = new socks5::conn();
        // 結束於該指針被非本函數釋放
        if(conn == nullptr) {
            utils::close_conn(conn, client_fd, "connection fail", false, &loopable);
            continue;
        }

        conn->loop = loop;
        conn->server = server;
        conn->client.fd = client_fd;

        ev_io_init(conn->client.rw, client_recv_cb, client_fd, EV_READ);
        ev_io_init(conn->client.ww, client_send_cb, client_fd, EV_WRITE);
        ev_io_start(loop, conn->client.rw);

        char ip[BUFFER_LEN];
        inet_ntop(addr.sin_family, &addr.sin_addr.s_addr, ip, BUFFER_LEN);
        utils::msg("host: " + *(new string(ip)) + "   "
                   + "port: " + to_string(ntohs(addr.sin_port)));

    } while(loopable);
}


void client_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *conn = (socks5::conn *)watcher->data;         // C/S's data 夾帶的是連接
    auto *server = conn->server;
    auto *client = &(conn->client);
    auto *remote = &(conn->remote);

    utils::msg("client_recv_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage) + '\n');

    // 拼接報文片段
    char buffer[BUFFER_LEN];
    ssize_t size;
    bool loopable = true;// 標記是否繼續循環
    do {
        size = read(fd, buffer, sizeof(buffer));

        if(size < 0) {
            utils::close_conn(conn, fd, "close conn.", true, &loopable);
            continue;
        }
        else if(size == 0) {
            utils::close_conn(conn, fd, "close conn.", false, &loopable);
            continue;
        }
        else {
            client->input.resize(client->input.size() + size);
            client->input += *(new string(buffer));
        }
    } while(loopable);
    std::cout << client->input.size() << std::endl;

    utils::msg("client_recv_cb finish here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage) + '\n');

    switch(conn->stage) {
        case socks5::STATUS_NEGO_METHODS: {
            socks5::method_request* method_req;
            // 報文格式轉換
            method_req = (socks5::method_request* )client->input.data();
            // 版本校驗
            std::cout << socks5::VERSION << method_req->ver;
            if(socks5::VERSION != method_req->ver) {
                utils::close_conn(conn, -1, "version error", false, nullptr);
                utils::display_stage(conn);
                return;
            }

            // 方法數長度校驗
            if(client->input.size() < method_req->nmethods + 2) {
                utils::msg("nmethod lackness.\n");
                return;
            }

            // 創建與 client 的回復
            socks5::method_response method_resp = {
                    socks5::VERSION,
                    socks5::METHOD_USERNAMEPASSWORD
            };

            for(int i = 0; i < method_req->nmethods; i++) {
                if(server->auth_method == method_req->methods[i]) {
                    method_resp.method = server->auth_method;
                    conn->server->auth_method = server->auth_method;
                }
            }
            utils::msg("auth method: "  + to_string(method_resp.method));
            std::string s((char*)&method_resp);
            client->output += s;

            // 如果協商結果不可用, 更改階段
            if (socks5::METHOD_NOACCEPTABLE_METHODS == method_resp.method) {
                conn->stage = socks5::STATUS_CLOSING;
            }

            // 清理接收緩存
            client->input.clear();
            ev_io_stop(loop, watcher);

            // 傳達回復 (回調 client_send_cb)
            ev_io_start(loop, client->ww);
            break;
        }
        default: {
            utils::msg("unvalid stage.");
        }
    }
}


void client_send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *conn = (socks5::conn *)watcher->data;
    auto *client = &(conn->client);
    auto *remote = &(conn->remote);

    utils::msg("client_send_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage) + '\n');

    // 由 client_recv_cb 觸發, 對 fd 進行寫操作

}