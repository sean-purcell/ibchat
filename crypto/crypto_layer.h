#ifndef IBCHAT_CRYPTO_CRYPTO_LAYER_H
#define IBCHAT_CRYPTO_CRYPTO_LAYER_H

#include <stdint.h>

#include "../inet/protocol.h"

struct con_crypto {
	struct con_handle con;
	uint64_t nonce;
	uint8_t send_symm_key[32];
	uint8_t recv_symm_key[32];
	uint8_t send_hmac_key[32];
	uint8_t recv_hmac_key[32];
};

void init_con_crypto

#endif

