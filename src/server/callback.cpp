//
// Created by qintairan on 18-12-8.
//

#include "callback.h"

const int BUFFER_LEN = 256;     // 默認 read 長度

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *server = (socks5::server *)watcher->data;     // accept 的信息夾帶 服務器屬性

    bool loopable = true;   // 標記是否繼續循環
    do {
        sockaddr_in addr;
        socklen_t len = sizeof(sockaddr_in);
        int client_fd = accept(fd, (sockaddr*)&addr, &len);
        if (client_fd == -1) {
            utils::close_conn(nullptr, client_fd, "accept error", true, &loopable);
            break;
        }

        if (utils::setSocketNonBlocking(client_fd) < 0) {
            utils::close_conn(nullptr, client_fd, "set nonblocking: ", true, nullptr);
            continue;
        }

        if(utils::setSocketReuseAddr(fd) < 0) {
            utils::close_conn(nullptr, client_fd, "set reuseaddr: ", true, nullptr);
            continue;
        }

        auto conn = new socks5::conn();
        // 結束於該指針被非本函數釋放
        if(conn == nullptr) {
            utils::close_conn(conn, client_fd, "connection fail", false, nullptr);
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

    utils::msg("client_recv_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    // 拼接報文片段
    char buffer[BUFFER_LEN];
    bool loopable = true;// 標記是否繼續循環
    do {
        ssize_t size = read(fd, buffer, sizeof(buffer));
        if(size < 0) {
            utils::close_conn(conn, fd, "close conn.", true, &loopable);
            continue;
        }
        else if(size == 0) {
            utils::close_conn(conn, fd, "close conn.", false, &loopable);
            continue;
        }
        else {
            utils::str_concat_char(client->input, buffer, size);
        }
    } while(loopable);

    utils::msg("client_recv_cb finish here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
    switch(conn->stage) {
        case socks5::STATUS_NEGO_METHODS: {
            // 報文格式轉換
            auto method_req = (socks5::method_request* ) &(client->input[0]);

            // 版本校驗
            if(socks5::VERSION != method_req->ver) {
                utils::msg("client ver: " + to_string(method_req->ver));
                utils::close_conn(conn, -1, "version error", false, nullptr);
                return;
            }

            // 方法數长度校验 (method数 + uint_8字段×2)
            if(sizeof(*method_req) + method_req->nmethods < method_req->nmethods + 2) {
                utils::msg("nmethod lackness.");
                return;
            }

            // 创建对 client 的回复
            socks5::method_response method_resp {};
            method_resp.ver = socks5::VERSION;
            method_resp.method = socks5::METHOD_NOACCEPTABLE_METHODS;

            // 方法匹配

            for(int i = 0; i < method_req->nmethods; i++) {
                if(server->auth_method == method_req->methods[i]) {
                    method_resp.method = server->auth_method;
                    conn->auth_method = server->auth_method;
                }
            }

            utils::msg("Auth method confirm: "  + to_string(method_resp.method));

            auto method_resp_seq = (char*)&method_resp;    // resp结构序列化
            utils::str_concat_char(client->output, method_resp_seq, sizeof(method_resp));

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
            break;
        }
    }
    utils::msg("client_recv_cb deal with stage, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
}


void client_send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *conn = (socks5::conn *)watcher->data;
    auto *client = &(conn->client);
    auto *remote = &(conn->remote);

    utils::msg("client_send_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    // 由 client_recv_cb 触发, 對 fd 进行写操作, 由于 write 一次未必写完, 将分多次写出
    size_t idx = 0;
    bool loopable = true;
    do {
        // output 已被发送完, 清空发送缓存
        if(client->output.length()-idx <= 0) {
            client->output.clear();
            ev_io_stop(loop, watcher);
            break;
        }
        ssize_t size = write(fd, &client->output[idx], client->output.length()-idx);
        if (size < 0) {
            utils::close_conn(conn, fd, "close conn.", true, &loopable);
            continue;
        }
        else {
            idx += size;
        }
    } while(loopable);

    switch(conn->stage) {
        case socks5::STATUS_NEGO_METHODS: {
            if(conn->server->auth_method == socks5::METHOD_USERNAMEPASSWORD){
                conn->stage = socks5::STATUS_UNAME_PASSWD;
                // 开始接收下一阶段客户端报文 ( UNAME/PASSWD )
                ev_io_start(loop, client->rw); break;
            }

        }
        default: break;
    }

    utils::msg("client_send_cb finish here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
}
