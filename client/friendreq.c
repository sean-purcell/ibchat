#include <stdio.h>

#include <ibcrypt/sha256.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/rsa.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "../util/line_prompt.h"
#include "../util/lock.h"

#include "cli.h"
#include "friendreq.h"
#include "uname.h"
#include "bg_manager.h"

static int send_pkey_req(struct server_connection *sc, uint8_t target[32]);
static int send_friendreq_message(struct server_connection *sc, uint8_t target[32], uint8_t *pkey, uint64_t pkeylen);
static int verify_pkey(char *target, uint8_t *pkey_bin, uint64_t pkey_len);

int send_friendreq(struct server_connection *sc) {
	int ret = 0;
	pkey_resp = NULL;

	/* prompt for a username */
	char *uname = getusername("friend name", stdout);
	if(uname == NULL) {
		fprintf(stderr, "failed to get friend name\n");
		return -1;
	}

	/* get the uid */
	uint8_t uid[32];
	sha256((uint8_t*)uname, strlen(uname) + 1, uid);

	if(send_pkey_req(sc, uid) != 0) {
		goto err;
	}

	set_mode(2);

	pthread_mutex_lock(&bg_lock);
	while(pkey_resp == NULL) {
		pthread_cond_wait(&bg_wait, &bg_lock);
	}
	set_mode(0);
	pthread_mutex_unlock(&bg_lock);

	if(pkey_resp->length < 0x29) {
		fprintf(stderr, "server returned invalid message\n");
		goto err;
	}

	if(pkey_resp->message[0] == 0xff) {
		printf("the server could not find the user you specified\n");
		goto end;
	}

	if(memcmp(&pkey_resp->message[1], uid, 32) != 0) {
		fprintf(stderr, "server returned public key for wrong user\n");
		goto err;
	}

	uint64_t pkeysize = rsa_pubkey_bufsize(decbe64(
		&pkey_resp->message[0x21]));

	if(pkeysize + 0x21 != pkey_resp->length) {
		fprintf(stderr, "server returned invalid message\n");
	}

	uint8_t *pkey_bin = &pkey_resp->message[0x21];

	/* verify the public key */
	if(verify_pkey(uname, pkey_bin, pkeysize) != 0) {
		goto err;
	}

	if(send_friendreq_message(sc, uid, pkey_bin, pkeysize) != 0) {
		goto err;
	}

	return 0;

	goto end;
err:
	ret = -1;
end:
	if(pkey_resp) free_message(pkey_resp);
	free(uname);
	return ret;
}

static int verify_pkey(char *target, uint8_t *pkey_bin, uint64_t pkey_len) {
	uint8_t hash[32];
	sha256(pkey_bin, pkey_len, hash);

	char hex[65];
	to_hex(hash, 32, hex);

	printf("please verify %s's public key fingerprint:\n"
		"%s\n"
		"does this match external verification? [y/n] ",
		target, hex);

	int ans = yn_prompt();
	if(ans == -1) {
		return -1;
	}
	if(ans == 0) {
		printf("friend request canceled\n");
		return -1;
	}

	return 0;
}

static int send_pkey_req(struct server_connection *sc, uint8_t target[32]) {
	uint8_t *message = malloc(1 + 0x20);
	if(message == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		return -1;
	}

	message[0] = 1;
	memcpy(&message[1], target, 0x20);

	if(send_message(sc->ch, &sc->keys, message, 0x21) != 0) {
		fprintf(stderr, "failed to send pkey request\n");
		return -1;
	}

	free(message);
	return 0;
}

static int send_friendreq_message(struct server_connection *sc, uint8_t target[32], uint8_t *pkey, uint64_t pkeylen) {
	fprintf(stderr, "NOT IMPLEMENTED YET %s:%d\n", __FILE__, __LINE__);
	return -1;
}

