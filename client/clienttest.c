#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include <libibur/endian.h>

#include "../inet/connect.h"
#include "../inet/protocol.h"

#include "../util/message.h"

#define PORT "30476"

int main(int argc, char **argv) {
	if(argc != 2) {
		fprintf(stderr, "%s <address>\n", argv[0]);
		return 1;
	}
	struct sock serv = client_connect(argv[1], PORT);
	if(serv.fd == -1) {
		if(errno == 0) {
			fprintf(stderr, "getaddrinfo failed\n");
		} else {
			perror("connect error");
		}

		return 1;
	}

	printf("connected to %s\n", serv.address);

	char buf[4096];
	size_t total = 0;
	while(total < 87) {
		ssize_t read = recv(serv.fd, &buf[total], 87 - total, 0);
		total += read;
	}

	printf("%zd\n", total);

	for(size_t i = 0; i < total; i++) {
		putchar(buf[i]);
	}
}

