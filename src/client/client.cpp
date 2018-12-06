//
// Created by qintairan on 18-12-5.
//

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <netinet/in.h>

const int PORT_NO = 3033;

int main() {
    int sd;
    struct sockaddr_in addr;
    int addr_len = sizeof(addr);
    std::string buffer = "";

// Create client socket
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        return -1;
    }

    bzero(&addr, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_NO);
    addr.sin_addr.s_addr = htons(INADDR_ANY);

// Connect to server socket
    if (connect(sd, (struct sockaddr *) &addr, sizeof addr) < 0) {
        perror("Connect error");
        return -1;
    }

    while (buffer != "q") {
        // Read input from user and send message to the server
        std::getline(std::cin, buffer);
        send(sd, &buffer[0], buffer.length(), 0);

        // Receive message from the server
        recv(sd, &buffer[0], buffer.length(), 0);
        std::cout << "message: " << buffer << std::endl;
    }

    return 0;
}