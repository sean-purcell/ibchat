#ifndef IBCHAT_CRYPTO_HANDSHAKE_H
#define IBCHAT_CRYPTO_HANDSHAKE_H

#include <stdint.h>

#include "crypto_layer.h"

#include "../inet/protocol.h"

#define INVALID_SIG        1
#define INVALID_DH_KEY     2
#define INVALID_KEY_HASH   3

int server_handshake(struct con_handle *con, RSA_KEY *rsa_key, struct keyset *keys);
int client_handshake(struct con_handle *con, RSA_PUBLIC_KEY *server_rsa_key, struct keyset *keys, int *res);

#endif

