#ifndef IBCHAT_INET_PROTOCOL_H
#define IBCHAT_INET_PROTOCOL_H

#include <pthread.h>

#include "message.h"

struct con_handle {
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

int connection_status(struct con_handle *con);
void end_connection(struct con_handle *con);
void init_connection(struct con_handle *con, int sockfd);
void destroy_connection(struct con_handle *con);

#endif

