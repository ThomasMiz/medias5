// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "util.h"

#define MAX_PENDING_CONNECTION_REQUESTS 5
#define SOURCE_PORT 1080
#define READ_BUFFER_SIZE 2048

void handleClient(int clientHandleSocket);

ssize_t recvFull(int fd, void* buf, size_t n, int flags) {
    size_t totalReceived = 0;
    do {
        ssize_t nowReceived = recv(fd, buf + totalReceived, n - totalReceived, flags);
        if (nowReceived < 0) {
            perror("[ERR] recv()");
            return -1;
        }

        if (nowReceived == 0)
            break;

        totalReceived += nowReceived;
    } while (totalReceived < n);

    return totalReceived;
}

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
        socklen_t clientAddressLen;
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

void handleClient(int clientHandleSocket) {
    ssize_t received;
    char receiveBuffer[READ_BUFFER_SIZE + 1];

    // Socks5 starts with the client sending VER, NMETHODS, followed by that amount of METHODS. Let's read VER and NMETHODS
    received = recvFull(clientHandleSocket, receiveBuffer, 2, 0);
    if (received < 2) {
        printf("[ERR] Client closed connection unexpectedly\n");
        return;
    }

    // Check that version is 5
    if (receiveBuffer[0] != 5) {
        printf("[ERR] Client specified invalid version: %d\n", receiveBuffer[0]);
        return;
    }

    // Read NMETHODS methods.
    int nmethods = receiveBuffer[1];
    received = recvFull(clientHandleSocket, receiveBuffer, nmethods, 0);
    if (received < nmethods) {
        printf("[ERR] Client closed connection unexpectedly\n");
        return;
    }

    // We check that the methods specified by the client contains method 0, which is "no authentication required"
    int hasValidAuthMethod = 0;
    printf("[INF] Client specified auth methods: ");
    for (int i = 0; i < nmethods; i++) {
        hasValidAuthMethod = hasValidAuthMethod || (receiveBuffer[i] == 0);
        printf("%x%s", receiveBuffer[i], i + 1 == nmethods ? "\n" : ", ");
    }

    // If the client didn't specify "no authentication required", send an error and wait for the client to close the connection.
    if (!hasValidAuthMethod) {
        printf("[ERR] No valid auth method detected!\n");
        if (send(clientHandleSocket, "\x05\xFF", 2, 0) < 2) {
            perror("[ERR] send()");
            return;
        }

        // shutdown(clientHandleSocket, SHUT_WR); //TODO: Investigate shutdown

        // Wait for the client to close the TCP connection
        printf("[INF] Waiting for client to close the connection.\n");
        while (recv(clientHandleSocket, receiveBuffer, READ_BUFFER_SIZE, 0) > 0) {}
        return;
    }

    // Tell the client we're using auth method 00 ("no authentication required")
    if (send(clientHandleSocket, "\x05\x00", 2, 0) < 2) {
        perror("[ERR] send()");
        return;
    }

    // The client can now start sending requests.

    // Read from a client request: VER, CMD, RSV, ATYP
    received = recvFull(clientHandleSocket, receiveBuffer, 4, 0);
    if (received < 4) {
        printf("[ERR] Client closed connection unexpectedly\n");
        return;
    }

    // Check that the CMD the client specified is X'01' "connect". Otherwise, send and error and close the TCP connection.
    if (receiveBuffer[1] != 1) {
        // The reply specified REP as X'07' "Command not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
        if (send(clientHandleSocket, "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0) < 10)
            perror("[ERR] send()");
        return;
    }

    // Check ATYP and print the address/domainname the client asked to connect to
    if (receiveBuffer[3] == 1) {
        // IPv4
        printf("[INF] Client asked to connect to IPv4: ");
        received = recvFull(clientHandleSocket, receiveBuffer, 6, 0);
        if (received < 6) {
            printf("[ERR] Client closed connection unexpectedly\n");
            return;
        }
        struct sockaddr_in s;
        memset(&s, 0, sizeof(s));
        s.sin_addr.s_addr = *((int*)&receiveBuffer[0]);
        printf("%s\n", inet_ntoa(s.sin_addr));
    } else if (receiveBuffer[3] == 3) {
        // Domain name
        printf("[INF] Client asked to connect to domain name: ");
        received = recv(clientHandleSocket, receiveBuffer, 1, 0);
        if (received < 1) {
            printf("[ERR] Client closed connection unexpectedly\n");
            return;
        }

        int domainNameLength = receiveBuffer[0];
        received = recvFull(clientHandleSocket, receiveBuffer, domainNameLength + 2, 0);
        if (received < domainNameLength + 2) {
            printf("[ERR] Client closed connection unexpectedly\n");
            return;
        }

        int port = ntohs(*((short*)&receiveBuffer[domainNameLength]));
        receiveBuffer[domainNameLength] = '\0';
        printf("%s:%d\n", receiveBuffer, port);
    } else if (receiveBuffer[3] == 4) {
        printf("[INF] Client asked to connect to IPv6: paja implementar el print xd");
    } else {
        // The reply specified REP as X'08' "Address type not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
        if (send(clientHandleSocket, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0) < 10)
            perror("[ERR] send()");
        return;
    }

    send(clientHandleSocket, "\x05\x00\x00\x01\x04\x03\x02\x01\x06\x05", 10, 0);

    const char* pedro = "HTTP/1.1 200 OK\nContent-Length: 13\n\nPedro McPedro";
    send(clientHandleSocket, pedro, strlen(pedro), 0);

    // Wait for the client to close the TCP connection
    printf("[INF] Waiting for client to close the connection.\n");
    while (recv(clientHandleSocket, receiveBuffer, READ_BUFFER_SIZE, 0) > 0) {}
}