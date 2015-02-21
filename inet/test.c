#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "protocol.h"
#include "../util/message.h"

int main() {
	pthread_t thread;

	struct connection con;
	con.sockfd = 1;
	con.out_queue = malloc(sizeof(struct message_queue));
	con.in_queue = malloc(sizeof(struct message_queue));
	con.out_mutex = malloc(sizeof(pthread_mutex_t));
	con.in_mutex = malloc(sizeof(pthread_mutex_t));

	pthread_create(&thread, NULL, handle_connection, &con);
}

