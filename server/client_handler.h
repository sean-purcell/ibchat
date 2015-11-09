#ifndef IBCHAT_SERVER_CLIENT_HANDLER_H
#define IBCHAT_SERVER_CLIENT_HANDLER_H

#include <pthread.h>

#include "../inet/message.h"

struct client_handler {
	pthread_t thread;

	int fd;
	uint8_t id[32];

	struct con_handle *hndl;
	struct keyset *keys;

	/* this will only be written to in one location, a mutex is overkill */
	int stop;

	/* for use in the handler table */
	struct client_handler *next;
};

int spawn_handler(int fd);

int init_handler_table();
void end_handlers();
void destroy_handler_table();
struct client_handler *get_handler(uint8_t* id);
int add_handler(struct client_handler *handler);
int rem_handler(uint8_t* id);

#endif

