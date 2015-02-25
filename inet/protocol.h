#ifndef IBCHAT_INET_PROTOCOL_H
#define IBCHAT_INET_PROTOCOL_H

#include <pthread.h>

#include "../util/message.h"

struct connection {
	int sockfd;
	struct message_queue out_queue;
	pthread_mutex_t out_mutex;
	struct message_queue in_queue;
	pthread_mutex_t in_mutex;
	uint64_t ka_last_recv;
	pthread_mutex_t kill_mutex;
	int kill;
};

void *handle_connection(void *_con);

int connection_status(struct connection *con);
void end_connection(struct connection *con);
void init_connection(struct connection *con, int sockfd);
void destroy_connection(struct connection *con);

#endif

