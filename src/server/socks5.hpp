//
// Created by qintairan on 18-12-7.
//

#ifndef GLORIOUSOCKS_SOCKS5_HPP
#define GLORIOUSOCKS_SOCKS5_HPP

#include <iostream>
using namespace std;

/* Socks5 struct [RFC 1928 / RFC 1929] */
namespace socks5 {

    const int VERSION           = 0x05;

    const int ADDRTYPE_IPV4     = 0x01;
    const int ADDRTYPE_DOMAIN   = 0x03;
    const int ADDRTYPE_IPV6     = 0x04;

// 认证协议
    const int AUTH_USERNAMEPASSWORD_VER           = 0x01;
    const int AUTH_USERNAMEPASSWORD_MAX_LEN       = 256;
    struct auth_request {
        uint8_t ver;        // 鉴定协议版本
        uint8_t ulen;       // 用户名长度
        string uname;       // 用户名
        uint8_t plen;       // 密码长度
        string passed;      // 密码
    };

    const int AUTH_USERNAMEPASSWORD_STATUS_OK     = 0x00;
    const int AUTH_USERNAMEPASSWORD_STATUS_FAIL   = 0x01;
    struct auth_response {
        uint8_t ver;        // 鉴定协议版本
        uint8_t status;     // 鉴定状态
    };

// 传输协议
    const int METHOD_NOAUTH                             = 0x00;
    const int METHOD_GSSAPI                             = 0x01;
    const int METHOD_USERNAMEPASSWORD                   = 0x02;
    const int METHOD_TOX7F_IANA_ASSIGNED                = 0x03;
    const int METHOD_TOXFE_RESERVED_FOR_PRIVATE_METHODS = 0x80;
    const int METHOD_NOACCEPTABLE_METHODS               = 0xff;

    struct method_request {
        uint8_t ver;        // socks版本（在socks5中是0x05）
        uint8_t nmethods;   // 在METHODS字段中出现的方法的数目
        uint8_t methods;    // 客户端支持的认证方式列表，每个方法占1字节
    };

    struct method_response {
        uint8_t ver;        // socks版本（在socks5中是0x05）
        uint8_t method;     // 服务端选中的方法（若返回0xFF表示没有方法被选中，客户端需要关闭连接）
    };

// socks5 请求
    const int REQUEST_CMD_CONNECT       = 0x01;
    const int REQUEST_CMD_BIND          = 0x02;
    const int REQUEST_CMD_UDPASSOCIATE  = 0x03;

    const int REQUEST_RSV               = 0x00;

    struct request {
        uint8_t ver;        // socks版本（在socks5中是0x05）
        uint8_t cmd;        /* SOCK的命令码：
                                CONNECT X’01’
                                BIND X’02’
                                UDP ASSOCIATE X’03’
                            */
        uint8_t rsv;        // 保留字段
        uint8_t atyp;       // 地址类型
        string dst_addr;    // 目的地址
        uint16_t dst_port;  // 目的端口
    };

// socks5 回应
    const int RESPONSE_REP_SUCCESS                 = 0x00;
    const int RESPONSE_REP_SERVER_FAILURE          = 0x01;
    const int RESPONSE_REP_CONN_NOT_ALLOWED        = 0x02;
    const int RESPONSE_REP_NETWORK_UNREACHABLE     = 0x03;
    const int RESPONSE_REP_HOST_UNREACHABLE        = 0x04;
    const int RESPONSE_REP_CONN_REFUSED            = 0x05;
    const int RESPONSE_REP_TTL_EXPIRED             = 0x06;
    const int RESPONSE_REP_COMMAND_NOT_SUPPORTED   = 0x07;
    const int RESPONSE_REP_ADDR_TYPE_NOT_SUPPORTED = 0x08;
    const int RESPONSE_REP_TOXFF_UNASSIGNED        = 0x09;

    const int RESPONSE_RSV                         = 0x00;

    struct response {
        uint8_t ver;        // socks版本（在socks5中是0x05）
        uint8_t rep;        /* 应答状态码：
                                X’00’ succeeded
                                X’01’ general socks server failure
                                X’02’ connection not allowed by ruleset
                                X’03’ Network unreachable
                                X’04’ Host unreachable
                                X’05’ Connection refused
                                X’06’ TTL expired
                                X’07’ Command not supported
                                X’08’ Address type not supported
                                X’09’ to X’FF’ unassigned
                            */
        uint8_t rsv;        // 保留字段 （需设置为X’00’）
        uint8_t atyp;       // 地址类型
        string bnd_addr;    // 服务器绑定的地址
        uint16_t bnd_;      // 服务器绑定的端口
    };
}
#endif //GLORIOUSOCKS_SOCKS5_HPP
