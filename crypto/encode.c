#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <ibcrypt/chacha.h>

#include "../util/message.h"

/* encrypts the given message using 256-bit chacha */
/* returns NULL in the case of failure */
struct message *encrypt_message(uint8_t key[32], uint64_t nonce, uint8_t *ptext, uint64_t len) {
	struct message *m = malloc(sizeof(struct message));
	if(m == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	m->message = malloc(len);
	if(m->message == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	m->len = len;
	m->seq_num = nonce;

	if(chacha_enc(key, 32, nonce, ptext, m->message, len) != 0) {
		free(m->message);
		free(m);
		return NULL;
	}

	return m;
}

/* decrypts the given message using 256-bit chacha */
/* returns non-zero in case of failure */
int decrypt_message(uint8_t key[32], struct message *m, uint8_t *out) {
	return chacha_dec(key, 32, m->seq_num, m->message, out, m->length);
}

