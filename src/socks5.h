#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#include <netdb.h>

int handleClient(int clientSocket);

int handleAuthNegotiation(int clientSocket);
int handleRequest(int clientSocket, struct addrinfo** addressConnectTo);
int handleConnectAndReply(int clientSocket, struct addrinfo** addressConnectTo);
int handleConnectionData(int clientSocket);

#endif