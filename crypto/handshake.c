#include <time.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
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
		return -1;
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
		return -1;
	}

	expand_keyset(keybuf, 1, keys);
	keys->nonce = 1; /* we already sent one message */

	/* hash the keys */
	sha256(keybuf, key_size, hash);

	/* create the challenge message */
	challenge_m = encrypt_message(keys, hash, hlen);
	if(challenge_m == NULL) {
		return -1;
	}

	add_message(con, challenge_m);
	challenge_m = NULL;

	/* we're done the handshake */
	return 0;
}

/* res indicates the results.  it is 0 if everything worked out fine, other
 * values are defined in the header
 * program failures have a return value of -1,
 * invalid states have a positive return value */
int client_handshake(struct connection *con, uint8_t **anchors, size_t num_anchors, RSA_PUB_KEY *server_key, RSA_PUB_KEY *anchor_key, struct *keyset keys, int *res) {
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
	uint8_t challenge_response[hlen];

	uint64_t server_key_size;
	uint64_t anchor_key_size;
	uint64_t sig_offset;
	size_t i;

	int ret;

	*res = 0;

	gettimeofday(&tv, NULL);
	start = utime(tv);

	/* wait for the cert message */
	cert_m = get_message(con, total_time);
	if(cert_m == NULL) {
		return -1;
	}

	/* verify the cert message */
	server_key_size = rsa_pubkey_bufsize(decbe64(cert_m->message));
	anchor_key_size = rsa_pubkey_bufsize(decbe64(&cert_m->message[server_key_size]));
	sig_offset = server_key_size + anchor_key_size;
	if(sig_offset > cert_m->length) {
		return -1;
	}

	/* expand the server key into its public key form */
	if(rsa_wire2pubkey(&cert_m->message[0], server_key_size,
		server_key) == 0) {
		return -1;
	}
	/* expand the anchor key into its public key form */
	if(rsa_wire2pubkey(&cert_m->message[server_key_size], anchor_key_size,
		anchor_key) == 0) {
		return -1;
	}

	/* verify the signature */
	int valid = 0;
	if((ret = rsa_pss_verify(anchor_key_size, &cert_m->message[sig_offset],
		cert_m->length - sig_offset, &cert_m->message[0], server_key_size,
		&valid)) != 0) {
		if(ret == MALLOC_FAIL) {
			errno = ENOMEM;
		} else if(ret == CRYPTOGRAPHY_FAIL) {
			errno = EINVAL;
		}
		return -1;
	}
	if(!valid) {
		/* we don't have a valid cert */
		*res = INVALID_SIG;
		return 1;
	}

	/* hash the anchor, see if we have it */
	sha256(&cert_m->message[server_key_size], anchor_key_size, hash);

	for(i = 0; i < num_anchors; i++) {
		if(!memcmp_ct(anchors[i], hash, hlen)) {
			/* we have a match */
			goto valid_anchor;
		}
	}

	/* we found no valid anchor */
	/* continue with the negotiation, let the client decide what to do */
	*res = NON_TRUSTED_ROOT;

valid_anchor:
	/* we're done with that message */
	free_message(cert_m);

	/* generate the keys */
	if(cs_rand(keybuf, key_size) != 0) {
		return -1;
	}

	expand_keyset(keybuf, 0, keys);
	keys->nonce = 1;

	/* encrypt this and send it over */
	/* we trust this public key, but check the size anyways */
	if(server_key->bits >= 1000000) return -1; /* this is unreasonable */
	keyset_m = alloc_message((server_key->bits + 7) / 8);
	if(rsa_oaep_encrypt(server_key, keybuf, key_size, keyset_m->message, keyset_m->length) != 0) {
		return -1;
	}
	add_message(con, keyset_m);
	keyset_m = NULL; /* don't hang on to it */

	/* hash the keybuf while we wait */
	sha256(keybuf, 128, hash);

	/* get the time again */
	gettimeofday(&tv, NULL);

	/* now wait for the response */
	challenge_m = get_message(con, total_time - (utime(tv) - start));
	if(challenge_m == NULL) {
		return -1;
	}

	/* the actual message is 32 bytes */
	ret = decrypt_message(keys, challenge_m, challenge_response, hlen);
	if(ret == -1) {
		return -1;
	}
	free_message(challenge_m);
	challenge_m = NULL;

	/* don't bother failing early if the MAC failed */
	ret |= memcmp_ct(hash, challenge_response, hlen);
	if(ret) {
		*res = BAD_CHALLENGE_RESP;	
	}

	return 0;
}

