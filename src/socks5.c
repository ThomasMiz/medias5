#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "socks5.h"

#define READ_BUFFER_SIZE 2048

static ssize_t recvFull(int fd, void* buf, size_t n, int flags) {
    size_t totalReceived = 0;

    while (totalReceived < n) {
        ssize_t nowReceived = recv(fd, buf + totalReceived, n - totalReceived, flags);
        if (nowReceived < 0) {
            perror("[ERR] recv()");
            return -1;
        }

        if (nowReceived == 0) {
            printf("[ERR] Failed to recv(), client closed connection unexpectedly\n");
            return -1;
        }

        totalReceived += nowReceived;
    }

    return totalReceived;
}

static ssize_t sendFull(int fd, const void* buf, size_t n, int flags) {
    size_t totalSent = 0;

    while (totalSent < n) {
        ssize_t nowSent = send(fd, buf + totalSent, n - totalSent, flags);
        if (nowSent < 0) {
            perror("[ERR] send()");
            return -1;
        }

        if (nowSent == 0) {
            printf("[ERR] Failed to send(), client closed connection unexpectedly\n");
            return -1;
        }

        totalSent += nowSent;
    }

    return totalSent;
}

int handleClient(int clientSocket) {
    if (handleAuthNegotiation(clientSocket))
        return -1;

    // The client can now start sending requests.

    struct addrinfo addressConnectTo;
    if (handleRequest(clientSocket, &addressConnectTo))
        return -1;
    
    if (handleConnectAndReply(clientSocket, &addressConnectTo))
        return -1;

    if (handleConnectionData(clientSocket))
        return -1;

    return 0;
}

int handleAuthNegotiation(int clientSocket) {
    ssize_t received;
    char receiveBuffer[READ_BUFFER_SIZE + 1];

    // Socks5 starts with the client sending VER, NMETHODS, followed by that amount of METHODS. Let's read VER and NMETHODS
    received = recvFull(clientSocket, receiveBuffer, 2, 0);
    if (received < 0)
        return -1;

    // Check that version is 5
    if (receiveBuffer[0] != 5) {
        printf("[ERR] Client specified invalid version: %d\n", receiveBuffer[0]);
        return -1;
    }

    // Read NMETHODS methods.
    int nmethods = receiveBuffer[1];
    received = recvFull(clientSocket, receiveBuffer, nmethods, 0);
    if (received < 0)
        return -1;

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
        if (sendFull(clientSocket, "\x05\xFF", 2, 0) < 0)
            return -1;

        // shutdown(clientSocket, SHUT_WR); //TODO: Investigate shutdown

        // Wait for the client to close the TCP connection
        printf("[INF] Waiting for client to close the connection.\n");
        while (recv(clientSocket, receiveBuffer, READ_BUFFER_SIZE, 0) > 0) {}
        return -1;
    }

    // Tell the client we're using auth method 00 ("no authentication required")
    if (sendFull(clientSocket, "\x05\x00", 2, 0) < 0)
        return -1;

    return 0;
}

int handleRequest(int clientSocket, struct addrinfo* addressConnectTo) {
    ssize_t received;
    char receiveBuffer[READ_BUFFER_SIZE + 1];

    // Read from a client request: VER, CMD, RSV, ATYP
    received = recvFull(clientSocket, receiveBuffer, 4, 0);
    if (received < 0)
        return -1;

    // Check that the CMD the client specified is X'01' "connect". Otherwise, send and error and close the TCP connection.
    if (receiveBuffer[1] != 1) {
        // The reply specified REP as X'07' "Command not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
        sendFull(clientSocket, "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    // Check ATYP and print the address/domainname the client asked to connect to
    if (receiveBuffer[3] == 1) {
        // IPv4
        printf("[INF] Client asked to connect to IPv4: ");
        received = recvFull(clientSocket, receiveBuffer, 6, 0);
        if (received < 0)
            return -1;
        struct sockaddr_in s;
        memset(&s, 0, sizeof(s));
        s.sin_addr.s_addr = *((int*)&receiveBuffer[0]);
        printf("%s\n", inet_ntoa(s.sin_addr));
    } else if (receiveBuffer[3] == 3) {
        // Domain name
        printf("[INF] Client asked to connect to domain name: ");
        received = recv(clientSocket, receiveBuffer, 1, 0);
        if (received < 1) {
            printf("[ERR] Client closed connection unexpectedly\n");
            return -1;
        }

        int domainNameLength = receiveBuffer[0];
        received = recvFull(clientSocket, receiveBuffer, domainNameLength + 2, 0);
        if (received < 0)
            return -1;

        int port = ntohs(*((short*)&receiveBuffer[domainNameLength]));
        receiveBuffer[domainNameLength] = '\0';
        printf("%s:%d\n", receiveBuffer, port);
    } else if (receiveBuffer[3] == 4) {
        printf("[INF] Client asked to connect to IPv6: paja implementar el print xd");
    } else {
        // The reply specified REP as X'08' "Address type not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
        sendFull(clientSocket, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    return 0;
}

int handleConnectAndReply(int clientSocket, struct addrinfo* addressConnectTo) {
    ssize_t received;
    char receiveBuffer[READ_BUFFER_SIZE + 1];

    // TODO: Actually conenct somewhere 💀

    // Send a server reply: SUCCESS, bound to IPv4 1.2.3.4:5
    if (sendFull(clientSocket, "\x05\x00\x00\x01\x01\x02\x03\x04\x00\x05", 10, 0) < 0)
        return -1;

    return 0;

}

int handleConnectionData(int clientSocket) {
    ssize_t received;
    char receiveBuffer[READ_BUFFER_SIZE + 1];

    // TODO: this lol

    // Connect to the requested server? Nah, here's a hardcoded response instead.
    const char* pedro = "HTTP/1.1 200 OK\nContent-Length: 13\n\nPedro McPedro";
    if (sendFull(clientSocket, pedro, strlen(pedro), 0) < 0)
        return -1;

    // Wait for the client to close the TCP connection
    printf("[INF] Waiting for client to close the connection.\n");
    do {
        received = recv(clientSocket, receiveBuffer, READ_BUFFER_SIZE, 0);
    } while (received  > 0);

    return 0;
}