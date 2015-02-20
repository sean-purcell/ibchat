#ifndef IBCHAT_INET_PROTOCOL_H
#define IBCHAT_INET_PROTOCOL_H

#include <pthread.h>

/* in util/message.h, it would be overkill to include it here */
struct message_queue;

struct connection {
	int sockfd;
	struct message_queue *out_queue;
	pthread_mutex_t *out_mutex;
	struct message_queue *in_queue;
	pthread_mutex_t *in_mutex;
};

#endif

