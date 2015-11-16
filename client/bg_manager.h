#ifndef CLIENT_BG_MANAGER_H
#define CLIENT_BG_MANAGER_H

#include <pthread.h>

extern pthread_t bg_manager;
extern pthread_mutex_t bg_lock;
extern pthread_cond_t bg_wait;

#endif

