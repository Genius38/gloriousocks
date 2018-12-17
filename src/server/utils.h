//
// Created by qintairan on 18-12-16.
//

#ifndef GLORIOUSOCKS_UTILS_H
#define GLORIOUSOCKS_UTILS_H

#include "socks5.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

namespace utils {
    /*
     * 用於結束連接, 參數 loopable 用於在 cb 函數中作爲終止循環的信號
     * 參數 fd 和 conn 爲 nullptr 或 -1 時不進行操作
     * 參數 msg 用於顯示信息, has_erro 表示是否輸出 errno
     */
    void close_conn(socks5::conn* conn, int fd,
                    const std::string& msg, bool has_errno,
                    bool* loopable);


    /*
     * 單純用於打印信息
     */
    void msg(const string& msg);


    /*
     * 設置網絡通信中 fd 爲非阻塞
     */
    int setSocketNonBlocking(int fd);


    /*
     * 設置網絡通信中 fd 可重用地址和端口 （防止error 98)
     */
    int setSocketReuseAddr(int fd);


    /*
     * 设置TCP_NODELAY选项
     * */
    int setTCPNoDelay(int fd);


    /*
     * 解决 string 与 char array 的相加
     * */
    void str_concat_char(std::string& str, char* ch, const ssize_t size);
}


#endif //GLORIOUSOCKS_UTILS_H
