#include <stdio.h>

#include <ibcrypt/sha256.h>

#include "../util/line_prompt.h"

#include "friendreq.h"
#include "uname.h"

static int send_pkey_req(struct server_connection *sc, uint8_t target[32]);
static int send_friendreq_message(struct server_connection *sc, uint8_t target[32], uint8_t *pkey, uint64_t pkeylen);

int send_friendreq(struct server_connection *sc) {
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

	/* insert wait for message here */

	uint8_t *pkey = NULL;
	uint64_t pkeylen = 0;

	if(send_friendreq_message(sc, uid, pkey, pkeylen) != 0) {
		goto err;
	}

	return 0;

	int ret = 0;
	goto end;
err:
	ret = -1;
end:
	free(uname);
	return ret;
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

