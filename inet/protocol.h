#ifndef IBCHAT_INET_PROTOCOL_H
#define IBCHAT_INET_PROTOCOL_H

#include <pthread.h>

#include "message.h"

struct con_handle;

void *handle_connection(void *_con);

int launch_handler(pthread_t *thread, struct con_handle **con, int fd);

int handler_status(struct con_handle *con);
void end_handler(struct con_handle *con);
void destroy_handler(struct con_handle *con);

struct message *get_message(struct con_handle *con, uint64_t timeout);
void add_message(struct con_handle *con, struct message *m);

#endif

