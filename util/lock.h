#ifndef IBCHAT_UTIL_LOCK_H
#define IBCHAT_UTIL_LOCK_H

#include <pthread.h>

struct lock {
	pthread_mutex_t use_state_mutex;
	pthread_cond_t use_state_cond;
	int use_state;
};

#define LOCK_STRUCT_INIT \
	{ PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0 };

void acquire_readlock(struct lock *l);

void release_readlock(struct lock *l);

void acquire_writelock(struct lock *l);

void release_writelock(struct lock *l);

int init_lock(struct lock *l);
void destroy_lock(struct lock *l);

#endif

