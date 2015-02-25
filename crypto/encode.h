#ifndef IBCHAT_CRYPTO_ENCODE_H
#define IBCHAT_CRYPTO_ENCODE_H

#include <stdint.h>

struct message *encrypt_message(uint8_t key[32], uint64_t nonce, uint8_t *ptext, uint64_t len);
int decrypt_message(uint8_t key[32], struct message *m, uint8_t *out);

#endif

