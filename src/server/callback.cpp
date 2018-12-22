//
// Created by qintairan on 18-12-8.
//

#include "callback.h"


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
        char ip[32];
        inet_ntop(addr.sin_family, &addr.sin_addr.s_addr, ip, 32);
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
    auto *conn = (socks5::conn *)watcher->data;
    auto *server = conn->server;
    auto *client = &(conn->client);
    auto *remote = &(conn->remote);

    utils::msg("client_recv_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    // 读取
    io::readFromFD(loop, watcher, fd, client->input);

    utils::msg("client_recv_cb finish here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));



    switch(conn->stage) {

    /* 1. 协商认证方法 */
        case socks5::STATUS_NEGO_METHODS: {
            // 结构体包含数组无法直接转型, 需要内存字节拆分
            auto ver = (uint8_t)(*(&client->input[0]));
            auto nmethods = (uint8_t)(*(&client->input[1]));
            auto methods = (char*)malloc(nmethods*sizeof(uint8_t));
            memcpy(methods, &client->input[2], nmethods);

            // 版本校驗
            if(socks5::VERSION != ver) {
                utils::msg("client ver: " + to_string(ver));
                utils::close_conn(conn, fd, "version error", false, nullptr);
                return;
            }

            // 创建对 client 的回复
            socks5::method_response method_resp {};
            method_resp.ver = socks5::VERSION;
            method_resp.method = socks5::METHOD_NOACCEPTABLE_METHODS;

            // 方法匹配 (经验上倒序匹配更快)
            for(int i = nmethods - 1; i >= 0; i--) {
                if(server->auth_method == methods[i]) {
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
            ev_io_stop(loop, watcher);
            client->input.clear();

            // 传达回复 (回調 client_send_cb)
            ev_io_start(loop, client->ww);

            break;
        }

    /* 2. 用户名密码认证 (如果是 NOAUTH 模式则直接 ESTABLISH_CONNECTION ) */
        case socks5::STATUS_UNAME_PASSWD: {
            // 结构体包含数组无法直接转型, 需要内存字节拆分
            auto ver = (uint8_t)(*(&client->input[0]));     // Default 0x01
            auto ulen = (uint8_t)(*(&client->input[1]));
            auto uname = (char*) malloc(ulen * sizeof(char) + 1);
            memcpy(uname, &client->input[2], ulen);
            auto plen = (uint8_t)(*(&client->input[2+ulen]));
            auto passwd = (char*) malloc(plen * sizeof(char) + 1);
            memcpy(passwd, &client->input[2+ulen+1], plen);

            uname[ulen] = '\0';
            passwd[plen] = '\0';

            std::string uname_str = *(new string(uname));
            std::string passwd_str = *(new string(passwd));
            utils::msg("[AUTH] uname:passwd -> " + uname_str + ":" + passwd_str);

            socks5::auth_response auth_resp {};
            auth_resp.ver = 0x01;
            auth_resp.status = 0x00;

            // 版本鉴定
            if (ver != socks5::AUTH_USERNAMEPASSWORD_VER) {
                utils::msg("auth version error.");
                auth_resp.status = 0x01;        // 设置status让client发起关闭
            }

            // 长度和正确性校验
            if((uname_str.length() != ulen || uname_str != conn->server->uname)
                && (passwd_str.length() != plen || passwd_str != conn->server->passwd)) {
                utils::msg("uname or passwd error");
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
            ev_io_stop(loop, watcher);
            client->input.clear();

            // 传达回复 (回調 client_send_cb)
            ev_io_start(loop, client->ww);

            break;
        }
    /*3. 建立连接, 与远端服务器取得联系*/
        case socks5::STATUS_ESTABLISH_CONNECTION: {
            // 结构体包含数组无法直接转型, 需要内存字节拆分

            // 版本校验
            auto ver = (uint8_t)(*(&client->input[0]));     // Socks5
            if (ver != socks5::VERSION) {
                utils::close_conn(conn, fd, "version error", false, nullptr);
                return;
            }


//            auto rsv = (uint8_t)(*(&client->input[2]));  // 保留字段 0X00
//            utils::msg("rsv: " + to_string(rsv));

            /* 检查地址类型： IPV4, 域名（需要解析）, IPV6 */
            auto atype = (uint8_t)(*(&client->input[3]));
            remote->atype = atype;

            // 创建对 remote 的回复
            socks5::response resp {};
            resp.ver = ver;
            resp.rep = socks5::RESPONSE_REP_SUCCESS;
            resp.atyp = atype;

            // 创建 sockaddr for remote
            struct sockaddr_in addr {};
            memset((char *)&addr, 0, sizeof(addr));

            // 命令码校验 (目前仅使用到 CONNECT)
            auto cmd = (uint8_t)(*(&client->input[1]));
            if (cmd != socks5::REQUEST_CMD_CONNECT) {
                resp.rep = socks5::RESPONSE_REP_COMMAND_NOT_SUPPORTED;
                // 序列化 resp 并直接回复
                auto resp_seq = (char*)&resp;
                utils::str_concat_char(client->output, resp_seq, sizeof(resp));
                ev_io_stop(loop, watcher);
                ev_io_start(loop, client->ww);
                utils::close_conn(conn, fd, "remote cmd error.", false, nullptr);
                return;
            }

            switch(atype) {
                case socks5::ADDRTYPE_IPV4: /* ipv4 */{
                    // ipv4 长度为 32 = 4Byte
                    auto dst_addr = (uint32_t*)malloc(4*sizeof(char));
                    memcpy(dst_addr, &client->input[4], 4);

                    auto *dst_port = (uint16_t*)malloc(sizeof(uint16_t));  // uint16_t转换到主机字节序
                    memcpy(dst_port, &client->input[8], 2);

                    // 检查地址与端口
                    char ipv4_addr_buf[32];
                    inet_ntop(AF_INET, dst_addr, ipv4_addr_buf, sizeof(ipv4_addr_buf));
                    utils::msg("[DETAILS] addr:port -> " + *(new string(ipv4_addr_buf)) +
                               ":" + to_string(ntohs(*dst_port)));

                    // 由于需要转发, 实际上没有必要对字节序进行处理
                    remote->addr = (char*)malloc(4*sizeof(char));
                    memcpy(remote->addr, &client->input[4], 4);
                    remote->port = *dst_port;

                    addr.sin_family = AF_INET;
                    addr.sin_port = *dst_port;
                    addr.sin_addr.s_addr = *dst_addr;

                    // 创建远端套接字
                    int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (remote_fd < 0) {
                        utils::close_conn(conn, remote_fd, "remote fd closed.", false, nullptr);
                        return;
                    }
                    // 设置非阻塞
                    if (utils::setSocketNonBlocking(remote_fd) < 0) {
                        utils::close_conn(nullptr, remote_fd, "remote set nonblocking: ", true, nullptr);
                        return;
                    }
                    // 设置地址复用
                    if(utils::setSocketReuseAddr(remote_fd) < 0) {
                        utils::close_conn(nullptr, remote_fd, "remote set reuseaddr: ", true, nullptr);
                        return;
                    }

                    // 建立TCP连接, remote_fd 则监听本次建立连接的端口 (Bind/Listen 是建立本地监听)
                    if (connect(remote_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                        /*
                         * #define EINPROGRESS 115
                         * The socket is nonblocking and the connection cannot be complete immediately.
                         * Since the connect() operation is already in progress,
                         * any subsequent operation on the socket is resulting into EINPROGRESS error code.
                         * 此处需要忽略 115 错误
                         * */
                        if((errno != EINPROGRESS)){
                            utils::close_conn(nullptr, remote_fd, "remote set reuseaddr: ", true, nullptr);
                            return;
                        }
                    }

                    // 清理接收緩存
                    ev_io_stop(loop, watcher);
                    client->input.clear();

                    remote->fd = remote_fd;

                    // 状态更变: 连接中
                    conn->stage = socks5::STATUS_CONNECTING;

                    // 将远端信息传递给 client (回調 remote_send_cb)
                    // 或将通信信息传递给 client
                    ev_io_init(remote->rw, remote_recv_cb, remote->fd, EV_READ);
                    ev_io_init(remote->ww, remote_send_cb, remote->fd, EV_WRITE);
                    ev_io_start(loop, remote->ww);

                    break;
                }
                case socks5::ADDRTYPE_DOMAIN: {

                    // TODO
                    // 取得域名长度(端口号位于之后)

                    break;
                }
                case socks5::ADDRTYPE_IPV6: {

                    // TODO

                    break;
                }
                default: break;
            }
            break;
        } // switch details
        case socks5::STATUS_STREAM: {
            // 接收 client 的请求并转发至 remote (回调 remote_send_cb)
            remote->output = client->input;
            client->input.clear();
            ev_io_start(loop, remote->ww);
            break;
        }
        default: {
            utils::msg("unvalid stage.");
            utils::close_conn(conn, fd, "closing conn", false, nullptr);
            break;
        }
    } // switch outtest
    utils::msg("client_recv_cb deal with stage, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
}


void client_send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *conn = (socks5::conn *)watcher->data;
    auto *client = &(conn->client);
    auto *remote = &(conn->remote);

    utils::msg("client_send_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    // 由于 write 一次未必写完, 将分多次写出
    io::writeToFD(loop, watcher, fd, client->output);
    switch(conn->stage) {
        case socks5::STATUS_NEGO_METHODS: {
            switch(conn->server->auth_method) {
                case socks5::METHOD_USERNAMEPASSWORD: {
                    conn->stage = socks5::STATUS_UNAME_PASSWD;
                    ev_io_start(loop, client->rw); break;
                }
                case socks5::METHOD_NOAUTH: {
                    conn->stage = socks5::STATUS_ESTABLISH_CONNECTION;  // Directly
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
            ev_io_start(loop, client->rw);
            break;
        }
        case socks5::STATUS_CONNETED: {
            conn->stage = socks5::STATUS_STREAM;
            ev_io_start(loop, client->rw);  // client 发送请求
            ev_io_start(loop, remote->rw);  // remote 发送数据
            break;
        }
        case socks5::STATUS_CLOSING: {
            utils::close_conn(conn, fd, "close conn.", false, nullptr);
            break;
        }
        default: break;
    }
    utils::msg("client_send_cb finish here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
}

void remote_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *conn = (socks5::conn *)watcher->data;
    auto *server = conn->server;
    auto *client = &(conn->client);
    auto *remote = &(conn->remote);

    utils::msg("remote_recv_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    // 读取 (true 表示会停止该 watcher)
    io::readFromFD(loop, watcher, fd, remote->input, true);

    utils::msg("remote_recv_cb finish here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    // 将数据转移至 client->output 并回调 client_send_cb 进行转发
    client->output += remote->input;
    remote->input.clear();

    // 将数据传至客户端
    ev_io_start(loop, client->ww);
}

void remote_send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *conn = (socks5::conn *)watcher->data;
    auto *server = conn->server;
    auto *client = &(conn->client);
    auto *remote = &(conn->remote);

    utils::msg("remote_send_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    switch(conn->stage) {
        // 连接阶段, 向client发送回应信息
        case socks5::STATUS_CONNECTING: {
            socks5::response resp {};
            resp.ver = socks5::VERSION;
            resp.rep = socks5::RESPONSE_REP_SUCCESS;
            resp.atyp = remote->atype;
            resp.rsv = 0x00;    // 保留字段
            resp.bnd_port = remote->port;
            if(remote->atype == socks5::ADDRTYPE_IPV4) {
                resp.bnd_addr = (char*) malloc(4*sizeof(char));
                memcpy(resp.bnd_addr, remote->addr, 4);
                // 检查地址与端口
                char ipv4_addr_buf[32];
                inet_ntop(AF_INET, resp.bnd_addr, ipv4_addr_buf, sizeof(ipv4_addr_buf));
                utils::msg("[CONNECTING] addr:port -> " + *(new string(ipv4_addr_buf)) +
                           ":" + to_string(ntohs(resp.bnd_port)));
            }
            if(remote->atype == socks5::ADDRTYPE_DOMAIN) {
                // TODO
            }
            if(remote->atype == socks5::ADDRTYPE_IPV6) {
                // TODO
            }

            // 序列化 resp
            /* 重要：此处序列化的长度应该为 4 + 4 + 2 = 10, 因为 resp 中有指针, 不能直接用 sizeof*/
            auto resp_seq = (char*)&resp;
            utils::str_concat_char(client->output, resp_seq, 4+4+2);
            // 至此连接已完成
            std::cout << "Connected." << std::endl;
            conn->stage = socks5::STATUS_CONNETED;

            ev_io_stop(loop, watcher);

            // 传达回复 (回調 client_send_cb)
            ev_io_start(loop, client->ww);


            utils::msg("remote_send_cb finish here(reply), fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
            return; // 这里需要直接 return, 避免 remote_fd 中的信息额外传回给远端
        }
        default: break;
    } // switch

    // 由于 write 一次未必写完, 将分多次写出
    io::writeToFD(loop, watcher, fd, remote->output);

    utils::msg("remote_send_cb end here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
}