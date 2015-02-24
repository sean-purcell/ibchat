#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include <libibur/endian.h>

#include "../inet/connect.h"
#include "../inet/protocol.h"

#include "../util/message.h"

#define PORT "30476"

int main(int argc, char **argv) {
	signal(SIGPIPE, SIG_IGN);
	struct sock serv = server_bind(PORT);
	if(serv.fd == -1) {
		if(errno == 0) {
			fprintf(stderr, "getaddrinfo failed\n");
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

	uint32_t ctr = 0;
	struct message m;
	m.message = malloc(256);
	sprintf((char*)m.message, "%d", 10);
	m.seq_num = 0;
	m.length = strlen((char*)m.message) + 1;
	pthread_mutex_lock(&con.out_mutex);
	message_queue_push(&con.out_queue, &m);
	pthread_mutex_unlock(&con.out_mutex);
	ctr++;
	while(pthread_kill(handler, 0) != ESRCH) {
		pthread_mutex_lock(&con.in_mutex);
		if(con.in_queue.size > 0) {
			struct message *in = message_queue_pop(&con.in_queue);
			printf("%llu: %s\n", in->seq_num, in->message);

			int a = atoi((char*)in->message);
			sprintf((char*)m.message, "%d", a * 3);
			m.seq_num = ctr;
			m.length = strlen((char*)m.message) + 1;

			pthread_mutex_lock(&con.out_mutex);
			message_queue_push(&con.out_queue, &m);
			pthread_mutex_unlock(&con.out_mutex);
			ctr++;
		}
		pthread_mutex_unlock(&con.in_mutex);

		usleep(500000);
	}
}

