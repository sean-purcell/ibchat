#ifndef IBCHAT_CRYPTO_HANDSHAKE_H
#define IBCHAT_CRYPTO_HANDSHAKE_H

#include <stdint.h>

#include "crypto_layer.h"

#include "../inet/protocol.h"

#define INVALID_SIG        1
#define INVALID_DH_KEY     2
#define INVALID_KEY_HASH   3

struct cert {
	uint64_t size;
	uint8_t *cert;
};

int server_handshake(struct connection *con, struct cert server_cert);
int client_handshake(struct connection *con, struct cert server_cert);

#endif

