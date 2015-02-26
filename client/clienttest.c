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

#include "../inet/message.h"

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

	struct con_handle con;

	init_handler(&con, serv.fd);

	pthread_t handler;
	pthread_create(&handler, NULL, handle_connection, &con);

	uint32_t ctr = 0;
	while(handler_status(&con) == 0) {
		struct message *in = get_message(&con, 0);
		if(in == NULL) continue;
		printf("%llu: %s\n", in->seq_num, in->message);
		int a = atoi((char*)in->message);
		struct message *out = alloc_message(256);
		sprintf((char*)out->message, "%d", a + 1);
		out->seq_num = ctr;
		out->length = strlen((char*)out->message) + 1;

		add_message(&con, out);

		ctr++;

		if(a > 256) end_handler(&con);
		pthread_mutex_unlock(&con.in_mutex);

		usleep(50000);
	}

	destroy_handler(&con);
}

