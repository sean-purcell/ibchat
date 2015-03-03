#ifndef IBCHAT_CRYPTO_CRYPTO_LAYER_H
#define IBCHAT_CRYPTO_CRYPTO_LAYER_H

#include <stdint.h>

#include "../inet/protocol.h"

#define INVALID_MAC 1

struct keyset {
	uint64_t nonce;
	uint8_t send_symm_key[32];
	uint8_t recv_symm_key[32];
	uint8_t send_hmac_key[32];
	uint8_t recv_hmac_key[32];
};

struct connection {
	struct con_handle handler;
	struct keyset     keys;
};

struct message *encrypt_message(struct keyset *keys, uint8_t *ptext, uint64_t plen);
int decrypt_message(struct keyset *keys, struct message *m, uint8_t *out, uint64_t outlen);
void expand_keyset(uint8_t *keybuf, int type, struct keyset *keys);

#endif
