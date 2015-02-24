#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <libibur/endian.h>

#include "../inet/connect.h"
#include "../inet/protocol.h"

#include "../util/message.h"

#define PORT "30476"

int main(int argc, char **argv) {
	signal(SIGPIPE, SIG_IGN);
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

	struct connection con;

	con.sockfd = serv.fd;
	con.in_queue = EMPTY_MESSAGE_QUEUE;
	con.out_queue = EMPTY_MESSAGE_QUEUE;
	pthread_mutex_init(&con.in_mutex, NULL);
	pthread_mutex_init(&con.out_mutex, NULL);

	pthread_t handler;
	pthread_create(&handler, NULL, handle_connection, &con);

	uint32_t ctr = 0;
	while(pthread_kill(handler, 0) != ESRCH) {
		struct message *m = malloc(sizeof(struct message));
		m->message = malloc(256);
		sprintf((char *)m->message, "%d", ctr);
		m->seq_num = ctr;
		m->length = strlen((char *)m->message) + 1;

		printf("acquiring out\n");
		pthread_mutex_lock(&con.out_mutex);
		printf("out acquired\n");
		message_queue_push(&con.out_queue, m);
		pthread_mutex_unlock(&con.out_mutex);
		printf("out released\n");

		printf("acquring in\n");
		pthread_mutex_lock(&con.in_mutex);
		printf("in acquired\n");
		while(con.in_queue.size > 0) {
			m = message_queue_pop(&con.in_queue);
			printf("%llu: %s\n", m->seq_num, m->message);
		}
		pthread_mutex_unlock(&con.in_mutex);
		printf("in released\n");

		ctr = (ctr + 1) % 256;
		sleep(1);
	}
}

