#ifndef IBCHAT_SERVER_CLIENT_HANDLER_H
#define IBCHAT_SERVER_CLIENT_HANDLER_H

#include <pthread.h>

#include "../inet/message.h"

struct client_handler {
	pthread_t thread;

	int fd;
	uint8_t id[32];
	struct message_queue send_queue;
	pthread_mutex_t send_mutex;

	/* for use in the handler table */
	struct client_handler *next;
};

int spawn_handler(int fd);

int init_handler_table();
void destroy_handler_table();
struct client_handler *get_handler(uint8_t* id);
int add_handler(struct client_handler *handler);
int rem_handler(uint8_t* id);

#endif

