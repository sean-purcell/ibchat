#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "connect.h"

#define CONNECT_BACKLOG (100)

static void *get_inet_address(struct sockaddr *addr) {
	switch(addr->sa_family) {
	case AF_INET:
		return &((struct sockaddr_in *) addr)->sin_addr;
	case AF_INET6:
		return &((struct sockaddr_in6 *) addr)->sin6_addr;
	default:
		return NULL;
	}
}

struct sock client_connect(char *address, char *port) {
	int ret;

	struct addrinfo hints;
	struct addrinfo *servinfo;
	struct addrinfo *server;

	struct sock con;

	memset(&hints, 0x00, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if((ret = getaddrinfo(address, port, &hints, &servinfo)) != 0) {
		errno = 0;
		con.fd = -1;
		return con;
	}

	for(server = servinfo; server != NULL; server = server->ai_next) {
		if((con.fd = socket(server->ai_family, server->ai_socktype,
			server->ai_protocol)) == -1) {
			continue;
		}

		if(connect(con.fd, server->ai_addr, server->ai_addrlen) != 0) {
			close(con.fd);
			continue;
		}

		break;
	}

	if(server == NULL) {
		errno = EIO;
		con.fd = -1;
		return con;
	}

	if(inet_ntop(server->ai_family, get_inet_address(server->ai_addr),
		con.address, sizeof(con.address)) == NULL) {
		close(con.fd);
		con.fd = -1;
		return con;
	}

	freeaddrinfo(servinfo);

	return con;
}

struct sock server_bind(char *port) {
	int ret;

	struct addrinfo hints;
	struct addrinfo *servinfo;
	struct addrinfo *server;

	struct sock con;

	memset(&hints, 0x00, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	if((ret = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
		errno = ret;
		con.fd = -2;
		return con;
	}

	for(server = servinfo; server != NULL; server = server->ai_next) {
		if((con.fd = socket(server->ai_family, server->ai_socktype,
			server->ai_protocol)) == -1) {
			continue;
		}

		int yes = 1;
		if(setsockopt(con.fd, SOL_SOCKET, SO_REUSEADDR, &yes,
			sizeof(yes)) == -1) {
			close(con.fd);
			continue;
		}

		if(bind(con.fd, server->ai_addr, server->ai_addrlen) == -1) {
			close(con.fd);
			continue;
		}

		if(listen(con.fd, CONNECT_BACKLOG) == -1) {
			close(con.fd);
			continue;
		}

		break;
	}

	if(server == NULL) {
		errno = EIO;
		con.fd = -1;
		return con;
	}

	if(inet_ntop(server->ai_family, get_inet_address(server->ai_addr),
		con.address, sizeof(con.address)) == NULL) {
		close(con.fd);
		con.fd = -1;
		return con;
	}

	freeaddrinfo(server);

	return con;
}

struct sock server_accept(int servfd) {
	struct sockaddr_storage client_addr;
	socklen_t sin_size;

	struct sock con;

	sin_size = sizeof(client_addr);
	if((con.fd = accept(servfd, (struct sockaddr *) &client_addr, &sin_size)) == -1) {
		return con;
	}

	if(inet_ntop(client_addr.ss_family, get_inet_address((struct sockaddr *) &client_addr),
		con.address, sizeof(con.address)) == NULL) {
		close(con.fd);
		con.fd = -1;
		return con;
	}

	return con;
}

