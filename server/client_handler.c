#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <ibcrypt/rand.h>

#include <libibur/endian.h>

#include "client_handler.h"
#include "chat_server.h"
#include "client_auth.h"

#include "../crypto/crypto_layer.h"
#include "../crypto/handshake.h"
#include "../inet/message.h"
#include "../util/defaults.h"
#include "../util/lock.h"

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

static int init_client_handler(void *_arg, struct client_handler *handler) {
	struct handler_arg *arg = (struct handler_arg *)_arg;

	handler->fd = arg->fd;
	handler->thread = arg->thread;

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

void ch_cleanup_end_handler(void *_arg) {
	struct ch_manager *arg = (struct ch_manager *)_arg;

	end_handler(&arg->handler);
	pthread_join(arg->thread, NULL);
}

void *client_handler(void *_arg) {
	struct client_handler c_hndl;
	struct ch_manager c_mgr;
	pthread_t ch_thread;
	struct keyset keys;

	int ret;

	if(init_client_handler(_arg, &c_hndl) != 0) {
		fprintf(stderr, "%d: failed to initialize client handler structure\n",
			((struct handler_arg *)_arg)->fd);
		goto err1;
	}

	/* initiate the connection handler thread */
	init_handler(&c_mgr.handler, c_hndl.fd);
	if(launch_handler(&ch_thread, &c_mgr.handler) != 0) {
		fprintf(stderr, "%d: failed to launch handler thread\n", c_hndl.fd);
		goto err2;
	}
	pthread_cleanup_push(ch_cleanup_end_handler, &c_mgr);

	/* complete the handshake */
	if((ret = client_handler_handshake(&c_mgr.handler, &keys)) != 0) {
		printf("%d: failed to complete handshake: %d\n", c_hndl.fd, ret);
		goto err3;
	}
	printf("%d: successfully completed handshake\n", c_hndl.fd);

	/* now we can start communicating with this user */
	if(auth_user(&c_hndl, &c_mgr.handler, &keys, &c_hndl) != 0) {
		goto err3;
	}

	/* thats it for now, sleep for a bit and then exit */
	sleep(5);

	printf("%d: exiting\n", c_hndl.fd);


	memset(&keys, 0, sizeof(struct keyset));
err3:
	pthread_cleanup_pop(1);
err2:
	destroy_handler(&c_mgr.handler);
	destroy_client_handler(&c_hndl);
err1:
	return NULL;
}

/* handler table data structure */
/* this table is used as a way to find the handler
 * associated with a given user to deliver them a message */
#define TOP_LOAD (0.75)
#define BOT_LOAD (0.5 / 2)

#define MAX_SIZE ((uint64_t)1 << 20)
#define MIN_SIZE ((uint64_t) 16)

struct handler_table {
	struct client_handler **buckets;
	uint64_t size; /* doubles as the modulus */

	uint64_t elements;

	struct lock l;
} ht;

static uint64_t hash_id(uint8_t *id) {
	uint8_t shasum[32];
	sha256(id, 32, shasum);

	return  decbe64(&shasum[ 0]) ^
	        decbe64(&shasum[ 8]) ^
	        decbe64(&shasum[16]) ^
		decbe64(&shasum[24]);
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

			uint64_t index = hash_id(cur->id) % nsize;
			cur->next = nbuckets[index];
			nbuckets[hash_id(cur->id) % nsize] = cur;

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

	if(init_lock(&ht.l) != 0) {
		return 1;
	}

	return 0;
}

void destroy_handler_table() {
	free(ht.buckets);
	destroy_lock(&ht.l);
}

struct client_handler *get_handler(uint8_t* id) {
	acquire_readlock(&ht.l);

	uint64_t index = hash_id(id) % ht.size;
	struct client_handler *cur = ht.buckets[index];

	while(cur != NULL) {
		if(cur->id == id) {
			goto exit;
		}

		cur = cur->next;
	}

exit:
	release_readlock(&ht.l);
	return cur;
}

int add_handler(struct client_handler *handler) {
	acquire_writelock(&ht.l);

	uint64_t index = hash_id(handler->id) % ht.size;
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
	release_writelock(&ht.l);
	return ret;
}

int rem_handler(uint8_t* id) {
	acquire_writelock(&ht.l);

	uint64_t index = hash_id(id) % ht.size;
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
	release_writelock(&ht.l);
	return ret;
}

