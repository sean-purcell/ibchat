#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include "../inet/connect.h"
#include "../inet/protocol.h"

#include "../util/message.h"

#define PORT "30476"

int main(int argc, char **argv) {
	struct sock serv = server_bind(PORT);
	if(serv.fd == -1) {
		if(errno == 0) {
			fprintf(stderr, "getaddrinfo failed");
		} else {
			perror("bind error");
		}

		return 1;
	}

	printf("server opened on local ip %s\n", serv.address);

	struct sock client = server_accept(serv.fd);
	if(client.fd == -1) {
		perror("accept error");

		return 1;
	}

	struct connection con;

	con.sockfd = client.fd;
	con.in_queue = EMPTY_MESSAGE_QUEUE;
	con.out_queue = EMPTY_MESSAGE_QUEUE;
	pthread_mutex_init(&con.in_mutex, NULL);
	pthread_mutex_init(&con.out_mutex, NULL);

	pthread_t handler;
	pthread_create(&handler, NULL, handle_connection, &con);
}

