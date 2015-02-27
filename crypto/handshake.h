#ifndef IBCHAT_CRYPTO_HANDSHAKE_H
#define IBCHAT_CRYPTO_HANDSHAKE_H

#include <stdint.h>

#include "crypto_layer.h"

#include "../inet/protocol.h"

/* this is the only one that's acceptable, and even then not great */
#define NON_TRUSTED_ROOT 1

#define INVALID_SIG 2
#define BAD_CHALLENGE_RESP 3

struct cert {
	uint64_t size;
	uint8_t *cert;
};

int server_handshake(struct connection *con, struct cert server_cert);
int client_handshake(struct connection *con, struct cert server_cert);

#endif

