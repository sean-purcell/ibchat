#ifndef IBCHAT_CRYPTO_HANDSHAKE_H
#define IBCHAT_CRYPTO_HANDSHAKE_H

#include <stdint.h>

#include "crypto_layer.h"

#include "../inet/protocol.h"

#define CRYPTO_FAIL 

struct cert {
	uint64_t size;
	uint8_t *cert;
};

int server_handshake(struct connection *con, struct cert server_cert);
int client_handshake(struct connection *con, struct cert server_cert);

#endif

