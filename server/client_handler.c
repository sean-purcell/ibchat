#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <ibcrypt/rsa_util.h>
#include <ibcrypt/rand.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/endian.h>

#include "client_handler.h"
#include "chat_server.h"
#include "client_auth.h"
#include "user_db.h"
#include "undelivered.h"

#include "../crypto/crypto_layer.h"
#include "../crypto/handshake.h"
#include "../inet/message.h"
#include "../util/defaults.h"
#include "../util/lock.h"
#include "../util/log.h"

struct handler_arg {
	pthread_t thread;
	int fd;
};

struct handler_table {
	struct client_handler **buckets;
	uint64_t size; /* doubles as the modulus */

	uint64_t elements;

	struct lock l;
} ht;

/* client handler cleanup */
struct ch_manager {
	struct con_handle *handler;
	pthread_t thread;
	int fd;
};

void *client_handler(void *_arg);
static int send_undelivered(uint8_t *id, struct ch_manager *c_mgr,
	struct keyset *keys);
static int client_handle_loop(struct client_handler *c_hndl,
	struct ch_manager *c_mgr, struct keyset *keys);
static int handle_message(struct message *m, struct client_handler *c_hndl);
static int send_u_notfound(struct client_handler *c_hndl, uint8_t *id);

int spawn_handler(int fd) {
	struct handler_arg *arg = malloc(sizeof(*arg));
	arg->fd = fd;

	pthread_attr_t handler_attributes;

	if(pthread_attr_init(&handler_attributes) != 0) {
		return -1;
	}
	pthread_attr_setdetachstate(&handler_attributes, PTHREAD_CREATE_JOINABLE);

	LOG("%d: spawning handler thread", fd);
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

	handler->stop = 0;

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

void ch_cleanup_end_handler(void *_arg) {
	struct ch_manager *arg = (struct ch_manager *)_arg;

	/* give them a chance to receive any left over messages */
	sleep(1);

	end_handler(arg->handler);
	pthread_join(arg->thread, NULL);

	close(arg->fd);
}

void keys_cleanup_end_handler(void *keys) {
	memsets(keys, 0, sizeof(struct keyset));
}

void ht_cleanup_end_handler(void *_arg) {
	struct client_handler *arg = (struct client_handler *) _arg;
	rem_handler(arg->id);

	if(arg->stop && ht.elements == 0) {
		destroy_handler_table();
	}
}

void *client_handler(void *_arg) {
	struct client_handler c_hndl;
	struct ch_manager c_mgr;
	struct keyset keys;

	int ret, fd;

	fd = ((struct handler_arg *)_arg)->fd;

	if(init_client_handler(_arg, &c_hndl) != 0) {
		ERR("%d: failed to initialize client handler structure",
			fd);
		goto err1;
	}

	/* initiate the connection handler thread */
	if(launch_handler(&c_mgr.thread, &c_mgr.handler, fd) != 0) {
		ERR("%d: failed to launch handler thread", fd);
		goto err2;
	}
	c_mgr.fd = fd;
	pthread_cleanup_push(ch_cleanup_end_handler, &c_mgr);

	/* complete the handshake */
	if((ret = client_handler_handshake(c_mgr.handler, &keys)) != 0) {
		LOG("%d: failed to complete handshake: %d", fd, ret);
		goto err3;
	}
	LOG("%d: successfully completed handshake", fd);
	pthread_cleanup_push(keys_cleanup_end_handler, &keys);

	/* now we can start communicating with this user */
	if(auth_user(&c_hndl, c_mgr.handler, &keys, c_hndl.id) != 0) {
		ERR("%d: failed to authorize user", fd);
		goto err4;
	}

	c_hndl.hndl = c_mgr.handler;
	c_hndl.keys = &keys;

	/* insert them into the user table */
	if(add_handler(&c_hndl) != 0) {
		ERR("%d: failed to add to the handler table", fd);
		goto err4;
	}
	pthread_cleanup_push(ht_cleanup_end_handler, &c_hndl);

	/* TODO: implement undelivered */
	if(send_undelivered(c_hndl.id, &c_mgr, &keys) != 0) {
		ERR("%d: failed to send undelivered messages", fd);
		/* this is an acceptable error
		 * we can continue to interact with the user */
	}

	if(client_handle_loop(&c_hndl, &c_mgr, &keys) != 0) {
		goto err5;
	}

	/* thats it for now */
err5:
	pthread_cleanup_pop(1); /* remove from the handler table */
err4:
	pthread_cleanup_pop(1); /* zero the keys */
err3:
	pthread_cleanup_pop(1); /* end the connection handler */
err2:
err1:
	LOG("%d: exiting", fd);
	return NULL;
}

static int send_undelivered(uint8_t *id, struct ch_manager *c_mgr,
	struct keyset *keys) {

	struct user *u = user_db_get(id);
	if(u == NULL) {
		return -1;
	}

	struct umessage *messages;
	if(undel_load(u, &messages) != 0) {
		return -1;
	}

	while(messages) {
		LOG("%d: sending undel message of length %llu",
			c_mgr->fd, messages->len);
		if(send_message(c_mgr->handler, keys,
			messages->message, messages->len) != 0) {

			free_umessage_list(messages);
			return -1;
		}
		struct umessage *next = messages->next;
		free_umessage(messages);
		messages = next;
	}

	return 0;
}

static int client_handle_loop(struct client_handler *c_hndl,
	struct ch_manager *c_mgr, struct keyset *keys) {

	/* while the connection is alive */
	while(handler_status(c_mgr->handler) == 0 && c_hndl->stop == 0) {
		struct message *m = recv_message(c_hndl->hndl, keys, 1000000ULL);
		if(m == NULL) continue;

		handle_message(m, c_hndl);
		free_message(m);
	}

	return 0;
}

static int handle_message(struct message *m, struct client_handler *c_hndl) {
	if(m->length < 33) {
		return -1;
	}

	uint8_t uid[32];
	memcpy(uid, &m->message[1], 32);

	switch(m->message[0]) {
	case 0: {
		struct user *u = user_db_get(uid);
		if(u == NULL) {
			/* user doesn't exist */
			if(send_u_notfound(c_hndl, uid) != 0) {
				return -1;
			}
			break;
		}

		/* sanity check the message length field */
		uint64_t payloadlen = decbe64(&m->message[1+0x20]);
		if(1+0x20+0x08+payloadlen != m->length) {
			ERR("%d: message length field does not "
				"claimed length", c_hndl->fd);
			return -1;
		}

		/* prepare the message to be sent to the end user */
		uint64_t resplen = 1 + 0x20 + 0x08 + payloadlen;
		uint8_t *resp = malloc(resplen);

		resp[0] = 0;
		memcpy(&resp[1], c_hndl->id, 0x20);
		encbe64(payloadlen, &resp[0x21]);
		memcpy(&resp[0x29], &m->message[0x29], payloadlen);

		struct client_handler *t_hndl = get_handler(uid);
		if(t_hndl == NULL) {
			/* user not logged in */
			if(undel_add_message(u, resp, resplen) != 0) {
				ERR("%d: failed to add to undel "
				"file", c_hndl->fd);
				return -1;
			}
			break;
		}

		if(send_message(t_hndl->hndl, t_hndl->keys,
			resp, resplen) != 0) {
			ERR("%d: failed to send message"
				"to target %d", c_hndl->fd, t_hndl->fd);
			return -1;
		}

		break;
	}
	case 1: {
		struct user *u = user_db_get(uid);
		if(u == NULL) {
			if(send_u_notfound(c_hndl, uid) != 0) {
				return -1;
			}
			break;
		}

		uint8_t *resp = malloc(1 + 0x20 +
			rsa_pubkey_bufsize(u->pkey.bits));

		if(resp == NULL) {
			ERR(
				"%d: failed to allocate memory",
				c_hndl->fd);
			return -1;
		}

		resp[0] = 1;
		memcpy(&resp[1], uid, 32);

		rsa_pubkey2wire(&u->pkey, &resp[0x21],
			rsa_pubkey_bufsize(u->pkey.bits));

		if(send_message(c_hndl->hndl, c_hndl->keys, resp, 0x21 +
			rsa_pubkey_bufsize(u->pkey.bits)) != 0) {	
			ERR(
				"%d: failed to send response",
				c_hndl->fd);
			return -1;
		}

		break;
	}
	default:
		ERR("%d: illegal message code %d",
			c_hndl->fd, m->message[0]);
		break;
	}

	return 0;
}

static int send_u_notfound(struct client_handler *c_hndl, uint8_t *uid) {
	uint8_t *resp = malloc(1 + 0x20);
	if(resp == NULL) {
		ERR(
			"%d: failed to allocate memory",
			c_hndl->fd);
		return -1;
	}

	resp[0] = 0xff;
	memcpy(&resp[1], uid, 32);

	if(send_message(c_hndl->hndl, c_hndl->keys, resp,
		1+0x20) != 0) {
		ERR(
			"%d: failed to send response",
			c_hndl->fd);

		free(resp);
		return -1;
	}

	free(resp);
	return 0;
}

/* handler table data structure */
/* this table is used as a way to find the handler
 * associated with a given user to deliver them a message */
#define TOP_LOAD (0.75)
#define BOT_LOAD (0.5 / 2)

#define MAX_SIZE ((uint64_t)1 << 20)
#define MIN_SIZE ((uint64_t) 16)

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

void end_handlers() {
	acquire_writelock(&ht.l);

	uint64_t i;
	for(i = 0; i < ht.size; i++) {
		struct client_handler *cur = ht.buckets[i];

		while(cur) {
			cur->stop = 1;
			cur = cur->next;
		}
	}
	release_writelock(&ht.l);
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
		if(memcmp(cur->id, id, 32) == 0) {
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
		if(memcmp((*loc)->id, handler->id, 32) == 0) {
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
		if(memcmp((*loc)->id, id, 32) == 0) {
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

