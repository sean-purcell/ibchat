#ifndef IBCHAT_INET_CONNECT_H
#define IBCHAT_INET_CONNECT_H

#include <arpa/inet.h>

struct connection {
	int fd;
	char address[INET6_ADDRSTRLEN];
};

int connect(char *address, char *port);
int open_host(char *port);
int accept_connection(int sockfd);

#endif

