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

#include "../inet/message.h"

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

	struct con_handle con;

	init_handler(&con, client.fd);

	pthread_t handler;
	pthread_create(&handler, NULL, handle_connection, &con);

	uint32_t ctr = 0;
	struct message *start = alloc_message(256);
	sprintf((char*)start->message, "%d", 10);
	start->seq_num = 0;
	start->length = strlen((char*)start->message) + 1;
	add_message(&con, start);
	ctr++;
	while(handler_status(&con) == 0) {
		struct message *in = get_message(&con, 0);
		if(in == NULL) continue;
		printf("%llu: %s\n", in->seq_num, in->message);
		int a = atoi((char*)in->message);
		struct message *out = alloc_message(256);
		sprintf((char*)out->message, "%d", a + 2);
		out->seq_num = ctr;
		out->length = strlen((char*)out->message) + 1;

		add_message(&con, out);

		ctr++;

		pthread_mutex_unlock(&con.in_mutex);

		usleep(50000);
	}

	destroy_handler(&con);
}

