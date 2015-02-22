#ifndef IBCHAT_INET_CONNECT_H
#define IBCHAT_INET_CONNECT_H

#include <arpa/inet.h>

struct sock {
	int fd;
	char address[INET6_ADDRSTRLEN];
};

struct sock client_connect(char *address, char *port);
struct sock server_bind(char *port);
struct sock server_accept(int sockfd);

#endif

