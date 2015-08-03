/* a thread-safe lock allowing for multiple readers or a single writer at any
 * given point in time */

#include <limits.h>
#include <assert.h>

#include "lock.h"

#define MAX_READERS (INT_MAX - 1)

void acquire_readlock(struct lock *l) {
	pthread_mutex_lock(&l->use_state_mutex);
	while(l->use_state < 0 || l->use_state == MAX_READERS) {
		pthread_cond_wait(&l->use_state_cond,
			&l->use_state_mutex);
	}
	l->use_state++;
	pthread_mutex_unlock(&l->use_state_mutex);
}

void release_readlock(struct lock *l) {
	pthread_mutex_lock(&l->use_state_mutex);
	assert(l->use_state > 0);
	l->use_state--;
	pthread_cond_broadcast(&l->use_state_cond);
	pthread_mutex_unlock(&l->use_state_mutex);
}

void acquire_writelock(struct lock *l) {
	pthread_mutex_lock(&l->use_state_mutex);
	while(l->use_state != 0) {
		pthread_cond_wait(&l->use_state_cond,
			&l->use_state_mutex);
	}
	l->use_state--;
	pthread_mutex_unlock(&l->use_state_mutex);
}

void release_writelock(struct lock *l) {
	pthread_mutex_lock(&l->use_state_mutex);
	assert(l->use_state == -1);
	l->use_state++;
	pthread_cond_broadcast(&l->use_state_cond);
	pthread_mutex_unlock(&l->use_state_mutex);
}

int init_lock(struct lock *l) {
	l->use_state = 0;
	return pthread_mutex_init(&l->use_state_mutex, NULL) |
		pthread_cond_init(&l->use_state_cond, NULL);
}

void destroy_lock(struct lock *l) {
	pthread_mutex_destroy(&l->use_state_mutex);
	pthread_cond_destroy(&l->use_state_cond);
}

