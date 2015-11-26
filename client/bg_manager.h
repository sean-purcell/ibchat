#ifndef CLIENT_BG_MANAGER_H
#define CLIENT_BG_MANAGER_H

#include <pthread.h>

#include "login_server.h"

extern pthread_t bg_manager;
extern pthread_mutex_t bg_lock;
extern pthread_cond_t bg_wait;

int start_bg_thread(struct server_connection *sc);

#endif

