// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socks5.h"
#include "util.h"

#define MAX_PENDING_CONNECTION_REQUESTS 5
#define SOURCE_PORT 1080

int main(int argc, const char* argv[]) {
    // Disable buffering on stdout and stderr
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    int serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket < 0) {
        perror("[ERR] socket()");
        exit(1);
    }

    struct sockaddr_in srcSocket;
    memset((char*)&srcSocket, 0, sizeof(srcSocket));

    srcSocket.sin_family = AF_INET;
    srcSocket.sin_port = htons(SOURCE_PORT);
    srcSocket.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr*)&srcSocket, sizeof(srcSocket)) != 0) {
        perror("[ERR] bind()");
        exit(1);
    }

    if (listen(serverSocket, MAX_PENDING_CONNECTION_REQUESTS) != 0) {
        perror("[ERR] listen()");
        exit(1);
    }

    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(serverSocket, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        char addrBuffer[128];
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        printf("[INF] Binding to %s\n", addrBuffer);
    } else
        perror("[WRN] Failed to getsockname()");

    while (1) {
        printf("Listening for next client...\n");

        struct sockaddr_storage clientAddress;
        socklen_t clientAddressLen = sizeof(clientAddress);
        int clientHandleSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressLen);
        if (clientHandleSocket < 0) {
            perror("[ERR] accept()");
            exit(1);
        } else {
            char addrBuffer[128];
            printSocketAddress((struct sockaddr*)&clientAddress, addrBuffer);
            printf("[INF] New connection from %s\n", addrBuffer);
        }

        handleClient(clientHandleSocket);

        close(clientHandleSocket);
    }
}