#include <time.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_err.h>

#include "handshake.h"
#include "crypto_layer.h"

#include "../inet/protocol.h"

/* don't import the whole file just for this */
uint64_t utime(struct timeval tv);

int server_handshake(struct connection *con, RSA_KEY *prikey, struct cert server_cert, struct keyset *keys) {
	struct message *cert_m;
	struct message *keyset_m;
	struct message *challenge_m;

	const uint64_t total_time = 5000000ULL;

	const size_t key_size = 128;
	uint8_t keybuf[keybuf_size];

	const size_t hlen = 32;
	uint8_t hash[hlen];

	/* send our signed cert */
	if((cert_m = alloc_message(server_cert.size)) == NULL) {
		return 0;
	}
	
	memcpy(cert_m->message, server_cert.cert, server_cert.size);
	cert_m->length = server_cert.size;
	cert_m->seq_num = 0; /* first message in the sequence */
	
	add_message(con, cert_m);
	cert_m = NULL; /* don't hang on to invalid pointer */

	/* wait for response, maximum 5 seconds */
	keyset_m = get_message(con, total_time);
	if(keyset_m == NULL) {
		return -1;
	}

	if(rsa_oaep_decrypt(prikey, keyset_m->cmessage, keyset_m->length, keybuf, key_size) != 0) {
		return 1;
	}

	memcpy(keys->recv_symm_key, &keybuf[0x00], 0x20);
	memcpy(keys->send_symm_key, &keybuf[0x20], 0x20);
	memcpy(keys->recv_hmac_key, &keybuf[0x40], 0x20);
	memcpy(keys->send_hmac_key, &keybuf[0x60], 0x20);
	keys->nonce = 1; /* we already sent one message */

	/* hash the keys */
	sha256(keybuf, key_size, hash);

	/* create the challenge message */
	challenge_m = encrypt_message(keys, hash, hlen);
	if(challenge_m == NULL) {
		return 1;
	}

	add_message(con, challenge_m);
	challenge_m = NULL;

	/* we're done the handshake */
	return 0;
}

int client_handshake(struct connection *con, RSA_PUB_KEY *anchors, size_t num_anchors, RSA_PUB_KEY *server_key, struct *keyset keys) {
	/* measure our starting time, we allow maximum 5 seconds for this */
	struct timeval tv;
	uint64_t start;

	const uint64_t total_time = 5000000ULL;

	struct message *cert_m;
	struct message *keyset_m;
	struct message *challenge_m;

	const size_t key_size = 128;
	uint8_t keybuf[keybuf_size];

	const size_t hlen = 32;
	uint8_t hash[hlen];

	uint64_t key_size;
	size_t i;

	int ret;

	gettimeofday(&tv, NULL);
	start = utime(tv);

	/* wait for the cert message */
	cert_m = get_message(con, total_time);
	if(cert_m == NULL) {
		return 1;
	}

	key_size = decbe64(cert_m->message);

	/* verify the cert message */
	for(i = 0; i < num_anchors; i++) {
		int valid = 0;
		if((ret = rsa_pss_verify(&anchors[i],
			&cert_m->message[8 + key_size], cert_m->length - 8 - key_size,
			&cert_m->message[8], key_size, &valid)) != 0) {

			if(ret == MALLOC_FAIL) {
				errno = ENOMEM;
				return -1;
			} else if(ret == CRYPTOGRAPHY_FAIL) {
				errno = EINVAL;
				return -1;
			}
		}

		if(valid) goto valid_cert; /* it validates */
	}

	/* we don't have a valid cert */
	errno = EINVAL;
	return 2;

valid_cert:
	/* expand the server key into a public key */
	if(rsa_wire2pubkey(&cert_m->message[8], key_size, server_key) == 0) {
		return -1;
	}

	/* generate the keys */
	if(cs_rand(keybuf, key_size) != 0) {
		return -1;
	}

	memcpy(keys->send_symm_key, &keybuf[0x00], 0x20);
	memcpy(keys->recv_symm_key, &keybuf[0x20], 0x20);
	memcpy(keys->send_hmac_key, &keybuf[0x40], 0x20);
	memcpy(keys->recv_hmac_key, &keybuf[0x60], 0x20);
	keys->nonce = 0;
}

