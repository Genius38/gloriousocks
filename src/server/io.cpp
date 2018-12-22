//
// Created by qintairan on 18-12-21.
//

#include "io.h"


const int BUFFER_LEN = 256;     // 默认 C char[] buffer长度


void io::readFromFD(struct ev_loop *loop, struct ev_io *watcher,
                    int fd, std::string& input, bool stop_watcher) {
    auto *conn = (socks5::conn *)watcher->data;
    char *buffer = (char*)malloc(BUFFER_LEN * sizeof(char));
    bool loopable = true;// 标记是否继续循环
    do {
        ssize_t size = read(fd, buffer, BUFFER_LEN);
        if(size < 0) {
            utils::close_conn(conn, -1, "close conn.", true, &loopable);
        }
        else if(size == 0) {    // 读到 EOF
            if(stop_watcher) {
                ev_io_stop(loop, watcher);
                conn->stage = socks5::STATUS_CLOSING;
                break;
            }
            else {
                utils::close_conn(conn, fd, "closed conn.", false, &loopable);
            }
        }
        else {
            utils::str_concat_char(input, buffer, size);
        }
    } while(loopable);

    free(buffer);
}


void io::writeToFD(struct ev_loop *loop, struct ev_io *watcher,
                   int fd, std::string& output) {
    auto *conn = (socks5::conn *)watcher->data;
    size_t idx = 0;
    bool loopable = true;
    do {
        // output 已被发送完, 清空发送缓存
        if(output.length()-idx <= 0) {
            output.clear();
            ev_io_stop(loop, watcher);
            break;
        }
        ssize_t size = write(fd, &output[idx], output.length()-idx);
        if (size < 0) {
            utils::close_conn(conn, fd, "close conn.", true, &loopable);
            break;
        }
        else {
            idx += size;
        }
    } while(loopable);
}