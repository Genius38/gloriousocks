//
// Created by qintairan on 18-12-8.
//

#include "callback.h"

const int BUFFER_LEN = 256;     // 默認 read 長度

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *server = (socks5::server *)watcher->data;     // accept 的信息夾帶 服務器屬性

    bool loopable = true;   // 循环标记
    do {
        sockaddr_in addr {};
        socklen_t len = sizeof(sockaddr_in);
        int client_fd = accept(fd, (sockaddr*)&addr, &len);

        if (client_fd == -1) {
            utils::close_conn(nullptr, client_fd, "accept error", true, &loopable);
            break;
        }

        // 链接信息
        char ip[BUFFER_LEN];
        inet_ntop(addr.sin_family, &addr.sin_addr.s_addr, ip, BUFFER_LEN);
        utils::msg("host: " + *(new string(ip)) + "   " + "port: " + to_string(ntohs(addr.sin_port)));

        // 设置非阻塞
        if (utils::setSocketNonBlocking(client_fd) < 0) {
            utils::close_conn(nullptr, client_fd, "set nonblocking: ", true, nullptr);
            continue;
        }

        // 设置地址复用
        if(utils::setSocketReuseAddr(client_fd) < 0) {
            utils::close_conn(nullptr, client_fd, "set reuseaddr: ", true, nullptr);
            continue;
        }

        auto conn = new socks5::conn();
        // 结束于该指针被其他函数析构
        if(conn == nullptr) {
            utils::close_conn(conn, client_fd, "connection fail", false, nullptr);
            continue;
        }

        conn->loop = loop;
        conn->server = server;
        conn->client.fd = client_fd;

        utils::msg("accept, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

        ev_io_init(conn->client.rw, client_recv_cb, client_fd, EV_READ);
        ev_io_init(conn->client.ww, client_send_cb, client_fd, EV_WRITE);

        ev_io_start(loop, conn->client.rw);

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
    char *buffer = (char*)malloc(BUFFER_LEN * sizeof(char));
    bool loopable = true;// 标记是否继续循环
    do {
        ssize_t size = read(fd, buffer, BUFFER_LEN);
        if(size < 0) {
            utils::close_conn(conn, fd, "close conn.", true, &loopable);
            continue;
        }
        else if(size == 0) {
            utils::close_conn(conn, fd, "closed conn.", false, &loopable);
            continue;
        }
        else {
            utils::str_concat_char(client->input, buffer, size);
        }
    } while(loopable);

    utils::msg("client_recv_cb finish here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    switch(conn->stage) {

    /* 1. 协商认证方法 */
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
                    break;
                }
            }
            utils::msg("Auth method confirm: "  + to_string(method_resp.method));

            // resp结构序列化
            auto method_resp_seq = (char*)&method_resp;
            utils::str_concat_char(client->output, method_resp_seq, sizeof(method_resp));

            // 如果協商結果不可用, 更改階段
            if (socks5::METHOD_NOACCEPTABLE_METHODS == method_resp.method) {
                conn->stage = socks5::STATUS_CLOSING;
            }

            // 清理接收緩存
            client->input.clear();
            free(buffer);
            ev_io_stop(loop, watcher);
            // 传达回复 (回調 client_send_cb)
            ev_io_start(loop, client->ww);

            break;
        }

    /* 2. 用户名密码认证 (如果是 NOAUTH 模式则直接 ESTABLISH_CONNECTION ) */
        case socks5::STATUS_UNAME_PASSWD: {
            // 结构体包含数组无法直接转型, 需要内存字节拆分
            auto ver = (uint8_t)(*(&client->input[0]));     // Default 0x01
            auto ulen = (uint8_t)(*(&client->input[1]));
            auto uname = (char*) malloc(ulen * sizeof(char));
            memcpy(uname, &client->input[2], ulen);
            auto plen = (uint8_t)(*(&client->input[2+ulen]));
            auto passwd = (char*) malloc(plen * sizeof(char));
            memcpy(passwd, &client->input[2+ulen+1], plen);

            std::string uname_str = *(new string(uname));
            std::string passwd_str = *(new string(passwd));
            utils::msg("[Stage2] uname:passwd -> " + uname_str + ":" + passwd_str);

            socks5::auth_response auth_resp {};
            auth_resp.ver = 0x01;
            auth_resp.status = 0x00;

            // 版本鉴定
            if (ver != socks5::AUTH_USERNAMEPASSWORD_VER) {
                utils::msg("[stage 2] auth version error");
                auth_resp.status = 0x01;
            }

            // 长度和正确性校验
            if((uname_str.length() != ulen || uname_str != conn->server->uname)
                && (passwd_str.length() != plen || passwd_str != conn->server->passwd)) {
                utils::msg("[stage 2] uname or passwd error");
                auth_resp.status = 0x01;
            }

            // 如果账户密码不可用, 更改阶段
            if (auth_resp.status == 0x01) {
                conn->stage = socks5::STATUS_CLOSING;
            }

            // resp结构序列化
            auto auth_resp_seq = (char*)&auth_resp;
            utils::str_concat_char(client->output, auth_resp_seq, sizeof(auth_resp));

            // 清理接收緩存
            client->input.clear();
            free(buffer);
            ev_io_stop(loop, watcher);
            // 传达回复 (回調 client_send_cb)
            ev_io_start(loop, client->ww);

            break;
        }
    /*3. 建立连接, 与远端服务器取得联系*/
        case socks5::STATUS_ESTABLISH_CONNECTION: {


        }
        default: {
            utils::msg("unvalid stage.");
            utils::close_conn(conn, fd, "closing conn", false, nullptr);
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

    // 由 client_recv_cb 触发, 對 fd 进行写操作
    // 由于 write 一次未必写完, 将分多次写出
    size_t idx = 0;
    bool loopable = true;
    do {
        // output 已被发送完, 清空发送缓存
        if(client->output.length()-idx <= 0) {
            // 清理发送缓存
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

    // 阶段处理
    switch(conn->stage) {
        case socks5::STATUS_NEGO_METHODS: {
            switch(conn->server->auth_method) {
                case socks5::METHOD_USERNAMEPASSWORD: {
                    conn->stage = socks5::STATUS_UNAME_PASSWD;
                    ev_io_start(loop, client->rw); break;
                }
                case socks5::METHOD_NOAUTH: {
                    ev_io_start(loop, client->rw); break;
                }
                case socks5::METHOD_GSSAPI: break;                              // 暂无
                case socks5::METHOD_TOX7F_IANA_ASSIGNED: break;                 // 暂无
                case socks5::METHOD_TOXFE_RESERVED_FOR_PRIVATE_METHODS: break;  // 暂无
                case socks5::METHOD_NOACCEPTABLE_METHODS: break;                // 不可到达
                default: break;
            }
            break;
        }
        case socks5::STATUS_UNAME_PASSWD: {
            conn->stage = socks5::STATUS_ESTABLISH_CONNECTION;
            ev_io_start(loop, client->rw); break;
        }
        default: break;
    }

    utils::msg("client_send_cb finish here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
}
