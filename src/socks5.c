#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <unistd.h>

#include "socks5.h"
#include "util.h"

#define READ_BUFFER_SIZE 2048
#define MAX_HOSTNAME_LENGTH 255

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

    struct addrinfo* connectAddresses;
    if (handleRequest(clientSocket, &connectAddresses))
        return -1;

    // Now we must conenct to the requested server and reply with success/error code.

    int remoteSocket = -1;
    if (handleConnectAndReply(clientSocket, &connectAddresses, &remoteSocket))
        return -1;

    // The connection has been established! Now the client and requested server can talk to each other.

    int status = handleConnectionData(clientSocket, remoteSocket);
    close(remoteSocket);
    return status;
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

int handleRequest(int clientSocket, struct addrinfo** connectAddresses) {
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

    char hostname[MAX_HOSTNAME_LENGTH + 1];
    int port = 0;
    struct addrinfo addrHints;
    memset(&addrHints, 0, sizeof(addrHints));
    addrHints.ai_socktype = SOCK_STREAM;
    addrHints.ai_protocol = IPPROTO_TCP;

    // Check ATYP and print the address/hostname the client asked to connect to
    if (receiveBuffer[3] == 1) {
        // IPv4
        received = recvFull(clientSocket, receiveBuffer, 6, 0);
        if (received < 0)
            return -1;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = *((in_addr_t*)&receiveBuffer[0]);
        addr.sin_port = *((in_port_t*)&receiveBuffer[4]);

        port = ntohs(addr.sin_port);
        inet_ntop(AF_INET, &addr.sin_addr, hostname, INET_ADDRSTRLEN);
        addrHints.ai_family = AF_INET;
    } else if (receiveBuffer[3] == 3) {
        // Domain name
        received = recvFull(clientSocket, receiveBuffer, 1, 0);
        if (received < 0)
            return -1;

        int hostnameLength = receiveBuffer[0];
        received = recvFull(clientSocket, hostname, hostnameLength + 2, 0);
        if (received < 0)
            return -1;

        port = ntohs(*((in_port_t*)&hostname[hostnameLength]));
        hostname[hostnameLength] = '\0';

    } else if (receiveBuffer[3] == 4) {
        received = recvFull(clientSocket, receiveBuffer, 18, 0);
        if (received < 0)
            return -1;

        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        memcpy(&addr.sin6_addr, receiveBuffer, 16);
        addr.sin6_port = *((in_port_t*)&receiveBuffer[16]);

        port = ntohs(addr.sin6_port);
        inet_ntop(AF_INET6, &addr.sin6_addr, hostname, INET6_ADDRSTRLEN);
        addrHints.ai_family = AF_INET6;
    } else {
        // The reply specified REP as X'08' "Address type not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
        sendFull(clientSocket, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    if (hostname == NULL) {
        char printBuf[128];
        printSocketAddress(addrHints.ai_addr, printBuf);
        printf("[INF] Client asked to connect to %s: %s\n", printFamily(&addrHints), printBuf);
    } else {
        printf("[INF] Client asked to connect to domain: %s:%d\n", hostname, port);
    }

    // For "service", we will indicate the port number
    char service[6] = {0};
    sprintf(service, "%d", port);

    printf("[INF] getaddrinfo hostname=%s, service=%s\n", hostname, service);

    int getAddrStatus = getaddrinfo(hostname, service, &addrHints, connectAddresses);
    if (getAddrStatus != 0) {
        printf("[ERR] getaddrinfo() failed: %s\n", gai_strerror(getAddrStatus));

        // The reply specifies ATYP as IPv4 and BND as 0.0.0.0:0.
        char errorMessage[10] = "\x05 \x00\x01\x00\x00\x00\x00\x00\x00";
        // We calculate the REP value based on the type of error returned by getaddrinfo
        errorMessage[1] =
            getAddrStatus == EAI_FAMILY   ? '\x08'  // REP is "Address type not supported"
            : getAddrStatus == EAI_NONAME ? '\x04'  // REP is "Host Unreachable"
                                          : '\x01'; // REP is "General SOCKS server failure"
        sendFull(clientSocket, errorMessage, 10, 0);
        return -1;
    }

    return 0;
}

int handleConnectAndReply(int clientSocket, struct addrinfo** connectAddresses, int* remoteSocket) {
    char addrBuf[64];
    int aipIndex = 0;
    for (struct addrinfo* aip = *connectAddresses; aip != NULL; aip = aip->ai_next) {
        printf("[INF] Option %i: %s (%s %s) %s %s (Flags: ", aipIndex, printFamily(aip), printType(aip), printProtocol(aip), aip->ai_canonname ? aip->ai_canonname : "-", printAddressPort(aip, addrBuf));
        printFlags(aip);
        printf(")\n");
    }

    int sock = -1;
    char addrBuffer[128];
    for (struct addrinfo* addr = *connectAddresses; addr != NULL && sock == -1; addr = addr->ai_next) {
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock < 0) {
            printf("[INF] Failed to create remote socket on %s\n", printAddressPort(addr, addrBuffer));
        } else {
            errno = 0;
            if (connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
                printf("[INF] Failed to connect() remote socket to %s: %s\n", printAddressPort(addr, addrBuffer), strerror(errno));
                close(sock);
                sock = -1;
            }

            printf("[INF] Successfully connected to: %s (%s %s) %s %s (Flags: ", printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuf));
            printFlags(addr);
            printf(")\n");
        }
    }

    freeaddrinfo(*connectAddresses);

    if (sock == -1) {
        printf("[ERR] Failed to connect to any of the available options.\n");
        // The reply specified REP as X'05' "Connection refused", ATYP as IPv4 and BND as 0.0.0.0:0.
        sendFull(clientSocket, "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    *remoteSocket = sock;

    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(sock, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        printf("[INF] Remote socket bound at %s\n", addrBuffer);
    } else
        perror("[WRN] Failed to getsockname() for remote socket");

    // TODO: Make this send the bound IP & PORT instead of fixed value
    // Send a server reply: SUCCESS, bound to IPv4 1.2.3.4:5
    if (sendFull(clientSocket, "\x05\x00\x00\x01\x01\x02\x03\x04\x00\x05", 10, 0) < 0)
        return -1;

    return 0;
}

int handleConnectionData(int clientSocket, int remoteSocket) {
    ssize_t received;
    char receiveBuffer[4096];

    struct pollfd pollFds[2];
    pollFds[0].fd = clientSocket;
    pollFds[0].events = POLLIN;
    pollFds[0].revents = 0;
    pollFds[1].fd = remoteSocket;
    pollFds[1].events = POLLIN;
    pollFds[1].revents = 0;

    int alive = 1;
    do {
        int pollResult = poll(pollFds, 2, -1);
        if (pollResult < 0) {
            printf("[ERR] Poll returned %d: ", pollResult);
            perror(NULL);
            return -1;
        }

        for (int i = 0; i < 2; i++) {
            if (pollFds[i].revents == 0)
                continue;

            received = recv(pollFds[i].fd, receiveBuffer, sizeof(receiveBuffer), 0);
            if (received <= 0) {
                alive = 0;
                break;
            } else {
                int otherSocket = pollFds[i].fd == clientSocket ? remoteSocket : clientSocket;
                send(otherSocket, receiveBuffer, received, 0);
            }
        }
    } while (alive);

    return 0;
}