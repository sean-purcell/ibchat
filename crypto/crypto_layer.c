#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/sha256.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "../inet/message.h"
#include "../inet/protocol.h"

#include "crypto_layer.h"

/* encrypts the given message using 256-bit chacha */
/* returns NULL in the case of failure */
struct message *encrypt_message(struct keyset *keys, uint8_t *ptext, uint64_t plen) {
	uint64_t length = 8 + plen + 32; /* message plus hmac */

	struct message *m = alloc_message(length);
	if(m == NULL) {
		return NULL;
	}

	m->length = length;
	m->seq_num = keys->nonce;

	encbe64(keys->nonce, m->message);
	chacha_enc(keys->send_symm_key, 32, keys->nonce, ptext, &m->message[8], plen);
	hmac_sha256(keys->send_hmac_key, 32, m->message, plen + 8, &m->message[8 + plen]);

	return m;
}

/* decrypts the given message using 256-bit chacha */
/* returns non-zero in case of failure */
int decrypt_message(struct keyset *keys, struct message *m, uint8_t *out, uint64_t outlen) {
	if(m->length < 40 || m->length > outlen + 40) {
		errno = EINVAL;
		return -1;
	}

	uint8_t mac[32];
	uint64_t plen = m->length - 40; /* 32 for mac and 8 for nonce */
	uint64_t nonce;

	hmac_sha256(keys->recv_hmac_key, 32, m->message, 8 + plen, mac);

	uint8_t res = memcmp_ct(mac, &m->message[8 + plen], 32);
	if(res != 0) {
		errno = EINVAL;
		return -1;
	}

	nonce = decbe64(m->message);

	chacha_dec(keys->recv_symm_key, 32, nonce, &m->message[8], out, plen);
	return 0;
}

int send_message(struct con_handle *con, struct keyset *keys, uint8_t *ptext, uint64_t plen) {
	struct message *m = encrypt_message(keys, ptext, plen);
	if(m == NULL) {
		return -1;
	}

	keys->nonce++;

	add_message(con, m);

	return 0;
}

struct message *recv_message(struct con_handle *con, struct keyset *keys, uint64_t timeout) {
	errno = 0;
	struct message *m = get_message(con, timeout);
	if(m == NULL) {
		return m;
	}

	struct message *m_pt = alloc_message(m->length - 40);
	if(m_pt == NULL) {
		free_message(m);
		return NULL;
	}

	if(decrypt_message(keys, m, m_pt->message, m_pt->length) != 0) {
		free_message(m_pt);
		free_message(m);
		return NULL;
	}

	free_message(m);

	return m_pt;
}

/* type: 0=client, 1=server */
void expand_keyset(uint8_t *keybuf, int type, struct keyset *keys) {
	switch(type) {
	case 0:
		memcpy(keys->send_symm_key, &keybuf[0x00], 0x20);
		memcpy(keys->recv_symm_key, &keybuf[0x20], 0x20);
		memcpy(keys->send_hmac_key, &keybuf[0x40], 0x20);
		memcpy(keys->recv_hmac_key, &keybuf[0x60], 0x20);
		break;
	case 1:
		memcpy(keys->recv_symm_key, &keybuf[0x00], 0x20);
		memcpy(keys->send_symm_key, &keybuf[0x20], 0x20);
		memcpy(keys->recv_hmac_key, &keybuf[0x40], 0x20);
		memcpy(keys->send_hmac_key, &keybuf[0x60], 0x20);
		break;
	default:
		/* bad */
		errno = EINVAL;
		break;
	}
}

