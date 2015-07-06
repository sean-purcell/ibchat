#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <ibcrypt/rand.h>

#include "client_handler.h"
#include "chat_server.h"

#include "../crypto/crypto_layer.h"
#include "../crypto/handshake.h"
#include "../inet/message.h"
#include "../util/defaults.h"

struct handler_arg {
	pthread_t thread;
	int fd;
};

void *client_handler(void *_arg);

int spawn_handler(int fd) {
	struct handler_arg *arg = malloc(sizeof(*arg));
	arg->fd = fd;

	pthread_attr_t handler_attributes;

	if(pthread_attr_init(&handler_attributes) != 0) {
		return -1;
	}
	pthread_attr_setdetachstate(&handler_attributes, PTHREAD_CREATE_JOINABLE);

	printf("%d: spawning handler thread\n", fd);
	if(pthread_create(&arg->thread, &handler_attributes, client_handler, arg) != 0) {
		return -1;
	}

	pthread_attr_destroy(&handler_attributes);

	return 0;
}

static uint64_t gen_handler_id() {
	uint64_t id;
	errno = 0;
	do {
		if(cs_rand_uint64(&id) != 0) {
			return 0;
		}
	} while(get_handler(id) != NULL);

	return id;
}

static int init_client_handler(void *_arg, struct client_handler *handler) {
	struct handler_arg *arg = (struct handler_arg *)_arg;

	handler->fd = arg->fd;
	handler->thread = arg->thread;

	/* generate an unused id */
	handler->id = gen_handler_id();
	if(errno != 0) {
		/* error occured */
		return -1;
	}

	/* initialize the send queue and send mutex */
	if(pthread_mutex_init(&handler->send_mutex, NULL) != 0) {
		return -1;
	}
	handler->send_queue = EMPTY_MESSAGE_QUEUE;

	/* free the argument */
	free(arg);

	return 0;
}

/* indicates the number of handshakes occuring at the same time */
int handshake_sem = 0;
pthread_mutex_t hs_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t hs_cond = PTHREAD_COND_INITIALIZER;

static int client_handler_handshake(struct con_handle *con, struct keyset *keys) {
	int ret;

	/* wait for a spot */
	{
		pthread_mutex_lock(&hs_mutex);
		while(handshake_sem == MAX_HANDSHAKES) {
			pthread_cond_wait(&hs_cond, &hs_mutex);
		}
		pthread_mutex_unlock(&hs_mutex);

		handshake_sem++;
	}

	ret = server_handshake(con, &server_key, keys);

	/* release our spot */
	{
		pthread_mutex_lock(&hs_mutex);
		handshake_sem--;
		pthread_cond_broadcast(&hs_cond);
		pthread_mutex_unlock(&hs_mutex);
	}

	return ret;
}

static void destroy_client_handler(struct client_handler *handler) {
	pthread_mutex_destroy(&handler->send_mutex);
}

/* client handler cleanup */
struct ch_manager {
	struct con_handle handler;
	pthread_t thread;
};

void *ch_cleanup_end_handler(void *_arg) {
	struct ch_manager *arg = (struct ch_manager *)_arg;

	end_handler(&arg->handler);
	pthread_join(&arg->thread, NULL);

	return NULL;
}

void *client_handler(void *_arg) {
	struct client_handler handler;
	struct ch_manager con_handler;
	pthread_t ch_thread;
	struct keyset keys;

	int ret;

	if(init_client_handler(_arg, &handler) != 0) {
		fprintf(stderr, "%d: failed to initialize client handler structure\n",
			((struct handler_arg *)_arg)->fd);
		goto err1;
	}

	if(add_handler(&handler) != 0) {
		fprintf(stderr, "%d: failed to add handler to table\n", handler.fd);
		goto err2;
	}

	/* initiate the connection handler thread */
	init_handler(&con_handler, handler.fd);
	if(launch_handler(&ch_thread, &con_handler) != 0) {
		fprintf(stderr, "%d: failed to launch handler thread\n", handler.fd);
		goto err3;
	}
	pthread_cleanup_push(ch_cleanup_end_handler, &con_handler);

	/* complete the handshake */
	if((ret = client_handler_handshake(&con_handler.handler, &keys)) != 0) {
		printf("%d: failed to complete handshake: %d\n", handler.fd, ret);
		goto err4;
	}
	printf("%d: successfully completed handshake\n", handler.fd);

	/* identify the user we're talking to */

	/* thats it for now, sleep for a bit and then exit */
	sleep(5);

	printf("%d: exiting\n", handler.fd);


	memset(&keys, 0, sizeof(struct keyset));
err4:
	pthread_cleanup_pop(1);
err3:
	destroy_handler(&con_handler);
	if(rem_handler(handler.id) != 0) {
		fprintf(stderr, "%d: the handler table has been corrupted\n", handler.fd);
	}
err2:
	destroy_client_handler(&handler);
err1:
	return NULL;
}

/* handler table data structure */
#define TOP_LOAD (0.75)
#define BOT_LOAD (0.5 / 2)

#define MAX_SIZE ((uint64_t)1 << 20)
#define MIN_SIZE ((uint64_t) 16)

#define MAX_READERS INT_MAX - 1

struct handler_table {
	struct client_handler **buckets;
	uint64_t size; /* doubles as the modulus */

	uint64_t elements;

	/* indicates number of readers */
	/* to read, wait until it becomes non-negative, and then increment */
	/* to write, wait until it becomes 0, and then decrement */
	pthread_mutex_t use_state_mutex;
	pthread_cond_t use_state_cond;
	int use_state;
} ht;

static void ht_acquire_readlock() {
	pthread_mutex_lock(&ht.use_state_mutex);
	while(ht.use_state < 0 || ht.use_state == MAX_READERS) {
		pthread_cond_wait(&ht.use_state_cond,
			&ht.use_state_mutex);
	}
	ht.use_state++;
	pthread_mutex_unlock(&ht.use_state_mutex);
}

static void ht_release_readlock() {
	pthread_mutex_lock(&ht.use_state_mutex);
	assert(ht.use_state > 0);
	ht.use_state--;
	pthread_cond_broadcast(&ht.use_state_cond);
	pthread_mutex_unlock(&ht.use_state_mutex);
}

static void ht_acquire_writelock() {
	pthread_mutex_lock(&ht.use_state_mutex);
	while(ht.use_state != 0) {
		pthread_cond_wait(&ht.use_state_cond,
			&ht.use_state_mutex);
	}
	ht.use_state--;
	pthread_mutex_unlock(&ht.use_state_mutex);
}

static void ht_release_writelock() {
	pthread_mutex_lock(&ht.use_state_mutex);
	assert(ht.use_state == -1);
	ht.use_state++;
	pthread_cond_broadcast(&ht.use_state_cond);
	pthread_mutex_unlock(&ht.use_state_mutex);	
}

static int resize_handler_table(uint64_t nsize) {
	if(nsize > MAX_SIZE || nsize < MIN_SIZE) {
		return 0;
	}

	size_t alloc_size = nsize * sizeof(struct client_handler *);
	struct client_handler **nbuckets = malloc(alloc_size);
	if(nbuckets == NULL) {
		return -1;
	}

	memset(nbuckets, 0, alloc_size);

	uint64_t i;

	for(i = 0; i < ht.size; i++) {
		struct client_handler *cur = ht.buckets[i];
		struct client_handler *next;
		while(cur != NULL) {
			next = cur->next;

			uint64_t index = cur->id % nsize;
			cur->next = nbuckets[index];
			nbuckets[cur->id % nsize] = cur;

			cur = next;
		}
	}

	free(ht.buckets);
	ht.buckets = nbuckets;
	ht.size = nsize;

	return 0;
}

int init_handler_table() {
	size_t size = MIN_SIZE * sizeof(struct client_handler *);
	ht.buckets = malloc(size);
	if(ht.buckets == NULL) {
		return 1;
	}
	memset(ht.buckets, 0, size);
	ht.size = MIN_SIZE;
	ht.elements = 0;

	ht.use_state = 0;
	if(pthread_cond_init(&ht.use_state_cond, NULL) != 0) {
		return 1;
	}
	if(pthread_mutex_init(&ht.use_state_mutex, NULL) != 0) {
		return 1;
	}

	return 0;
}

void destroy_handler_table() {
	free(ht.buckets);
	pthread_cond_destroy(&ht.use_state_cond);
	pthread_mutex_destroy(&ht.use_state_mutex);
}

struct client_handler *get_handler(uint64_t id) {
	ht_acquire_readlock();

	uint64_t index = id % ht.size;
	struct client_handler *cur = ht.buckets[index];

	while(cur != NULL) {
		if(cur->id == id) {
			goto exit;
		}

		cur = cur->next;
	}

exit:
	ht_release_readlock();
	return cur;
}

int add_handler(struct client_handler *handler) {
	ht_acquire_writelock();

	uint64_t index = handler->id % ht.size;
	struct client_handler **loc = &ht.buckets[index];

	int ret = 0;

	while(*loc != NULL) {
		/* don't tolerate duplicates */
		if((*loc)->id == handler->id) {
			ret = 1;
			goto exit;
		}

		loc = &((*loc)->next);
	}

	handler->next = NULL;
	*loc = handler;
	ht.elements++;

	if(ht.elements >
		(uint64_t) (ht.size * TOP_LOAD)) {
		/* resize */
		ret = resize_handler_table(ht.size << 1);
	}

exit:
	ht_release_writelock();
	return ret;
}

int rem_handler(uint64_t id) {
	ht_acquire_writelock();

	uint64_t index = id % ht.size;
	struct client_handler **loc = &ht.buckets[index];

	int ret = 0;

	while(*loc != NULL) {
		if((*loc)->id == id) {
			break;
		}

		loc = &((*loc)->next);
	}

	/* didn't find it */
	if(*loc == NULL) {
		ret = 1;
		goto exit;
	}

	/* we don't allocate the memory, so don't free it */
	*loc = (*loc)->next;
	ht.elements--;

	if(ht.elements <
		(uint64_t) (ht.size * BOT_LOAD)) {
		ret = resize_handler_table(ht.size >> 1);
	}

exit:
	ht_release_writelock();
	return ret;
}

