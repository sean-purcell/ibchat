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

void *client_handler(void *_arg) {
	struct client_handler handler;
	if(init_client_handler(_arg, &handler) != 0) {
		fprintf(stderr, "%d: failed to initialize client handler structure\n",
			((struct handler_arg *)_arg)->fd);
		goto err1;
	}

	int ret;

	struct con_handle con_handler;
	pthread_t ch_thread;
	struct keyset keys;

	/* initiate the connection handler thread */
	init_handler(&con_handler, handler.fd);
	if(launch_handler(&ch_thread, &con_handler) != 0) {
		fprintf(stderr, "%d: failed to launch handler thread\n", handler.fd);
		goto err2;
	}

	/* complete the handshake */
	if((ret = client_handler_handshake(&con_handler, &keys)) != 0) {
		printf("%d: failed to complete handshake: %d\n", handler.fd, ret);
		goto err3;
	}
	printf("%d: successfully completed handshake\n", handler.fd);

	/* now we can start communicating with this user */
	begin_interaction(&handler, &con_handler, &keys);

	/* thats it for now, sleep for a bit and then exit */
	sleep(5);

	printf("%d: exiting\n", handler.fd);


	memset(&keys, 0, sizeof(struct keyset));
err3:
	end_handler(&con_handler);
	pthread_join(ch_thread, NULL);
err2:
	destroy_handler(&con_handler);
	destroy_client_handler(&handler);
err1:
	return NULL;
}

int begin_interaction(struct client_handler *cli_hndl, struct con_handle *con_hndl, struct keyset *keys) {
#define ERR(x) fprintf(stderr, "%d: %s\n", cli_hndl->fd, x)

	uint8_t challenge[0x20];

	struct message *cli_response;

	uint8_t uid[0x20];
	RSA_PUBLIC_KEY pb_key;

	/* generate 256 bit challenge numbers and send them */
	{
		if(cs_rand(challenge, 0x20) != 0) {
			/* failed to generate random numbers, we should exit */
			/* TODO: make this more severe */
			ERR("generating random numbers failed, exit ASAP");
			goto err1;
		}

		if(send_message(con_hdnl, keys, challenge, 0x20) != 0) {
			ERR("failed to allocate message");
			goto err1;
		}
	}

	/* now we wait for the response */
	/* we shouldn't wait more than 10 seconds, the client shouldn't be busy */

	/* handle response */
	{
		cli_response = recv_message(con_hndl, keys, 10000000ULL);

		uint8_t *pb_key_bin = &cli_response->message[0x20];
		uint64_t keylen = rsa_pubkey_size(decbe64(pb_key_bin));

		if(0x20 + keylen + 0x20 + 0x08 >= cli_response->length) {
			/* invalid message, exit now */
			ERR("invalid length message");
			goto err2;
		}

		/* check the challenge bits */
		uint8_t *challenge_cli = &cli_response->message[0x20 + keylen];

		if(memcmp_ct(challenge, challenge_cli, 0x20) != 0) {
			ERR("invalid challenge bytes");
			goto err2;
		}

		uint8_t *sig_bin = &cli_response->message[0x20 + keylen + 0x20 + 0x08];
		uint64_t siglen = decbe64(&cli_response->message[0x20 + keylen + 0x20]);

		if(0x20 + keylen + 0x20 + 0x08 + siglen != cli_response->length) {
			/* invalid message, exit now */
			ERR("invalid length message");
			goto err2;
		}

		/* now parse the public key */
		if(rsa_wire2pubkey(pb_key_bin, keylen, &pbkey) != 0) {
			/* failed to read key, we should exit */
			ERR("failed to read public key");
			goto err2;
		}

		/* now check the signature */
		int valid = 0;
		rsa_pss_verify(&pb_key, sig_bin, siglen, cli_response->message, 0x20 + keylen + 0x08, &valid);

		if(!valid) {
			ERR("invalid signature");
			goto err3;
		}

		memcpy(uid, cli_response->message, 0x20);
	}

	/* now we have a uid and public key, identify this user */
	int ret = check_user(uid, &pb_key);

	memset(challenge, 0, sizeof(challenge));
	memset(uid, 0, sizeof(uid));

	rsa_free_pubkey(&pb_key);
	free_message(cli_response);

	return 0;

err3:
	rsa_free_pubkey(&pb_key);
err2:
	free_message(cli_response);
err1:
	memset(challenge, 0, sizeof(challenge));
	memset(uid, 0, sizeof(uid));
	return -1;
}

/* handler table data structure */
/* this table is used as a way to find the handler
 * associated with a given user to deliver them a message */
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

static uint64_t hash_id(uint8_t *id) {
	return  decbe64(&id[ 0]) ^
		decbe64(&id[ 8]) ^
		decbe64(&id[16]) ^
		decbe64(&id[24]);
}

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

struct client_handler *get_handler(uint8_t* id) {
	ht_acquire_readlock();

	uint64_t index = hash_id(id) % ht.size;
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
	ht_release_writelock();
	return ret;
}

int rem_handler(uint8_t* id) {
	ht_acquire_writelock();

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
	ht_release_writelock();
	return ret;
}

