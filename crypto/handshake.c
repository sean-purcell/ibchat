#include <stdlib.h>

#include <sys/time.h>

#include <ibcrypt/dh.h>
#include <ibcrypt/dh_util.h>
#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_err.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "handshake.h"
#include "crypto_layer.h"

#include "../inet/protocol.h"

/* don't import the whole file just for this */
extern uint64_t utime(struct timeval tv);

#ifdef NOT_IMPL
int server_handshake(struct connection *con, RSA_KEY *prikey, struct cert server_cert, struct keyset *keys) {
	struct message *cert_m;
	struct message *keyset_m;
	struct message *challenge_m;

	const uint64_t total_time = 5000000ULL;

	const size_t key_size = 128;
	uint8_t keybuf[key_size];

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
#endif

/* res indicates the results.  it is 0 if everything worked out fine, other
 * values are defined in the header
 * program failures have a return value of -1,
 * invalid states have a positive return value */
int client_handshake(struct con_handle *con, RSA_PUBLIC_KEY *server_rsa_key, struct keyset *keys, int *res) {
	/* measure our starting time, we allow maximum 5 seconds for this */
	struct timeval tv;
	uint64_t start;

	const uint64_t total_time = 5000000ULL;

	struct message *client_m;
	struct message *server_m;

	const size_t key_size = 128;
	uint8_t key_buf[key_size];

	const size_t hlen = 32;
	uint8_t hash[hlen];

	uint8_t *rsa_sk;
	uint64_t rsa_sk_size;
	uint8_t *dh_sk;
	uint64_t dh_sk_size;

	DH_CTX dh_ctx;
	DH_PUB dh_server_key = DH_VAL_INIT;
	DH_PUB dh_public_key = DH_VAL_INIT;
	DH_PRI dh_priv_exp = DH_VAL_INIT;
	DH_VAL dh_secret = DH_VAL_INIT;

	uint8_t *dh_secret_buf;
	uint64_t dh_secret_size;

	uint64_t sig_offset;

	int ret;

	*res = 0;

	gettimeofday(&tv, NULL);
	start = utime(tv);

	/* initialize our DH context */
	if(dh_init_ctx(&dh_ctx, 14) != 0) {
		return -1;
	}
	if(dh_gen_exp(&dh_ctx, &dh_priv_exp) != 0) {
		return -1;
	}
	if(dh_gen_pub(&dh_ctx, &dh_priv_exp, &dh_public_key) != 0) {
		return -1;
	}

	/* send the public key message */
	client_m = alloc_message(dh_valwire_bufsize(&dh_public_key));
	if(client_m == NULL) {
		return -1;
	}

	if(dh_val2wire(&dh_public_key, client_m->message, client_m->length) != 0) {
		return -1;
	}

	add_message(con, client_m);
	client_m = NULL;

	/* wait for the response */
	gettimeofday(&tv, NULL);
	server_m = get_message(con, total_time - (utime(tv) - start));
	if(server_m == NULL) {
		return -1;
	}

	rsa_sk = &server_m->message[8];
	rsa_sk_size = decbe64(&server_m[0]);

	dh_sk = &server_m->message[16 + rsa_sk_size];
	dh_sk_size = decbe64(&server_m->message[8 + rsa_sk_size]);

	if(dh_sk_size > (dh_ctx.bits + 7) / 8) {
		*res = INVALID_DH_KEY;
		return 1;
	}

	if(dh_wire2val(dh_sk, dh_sk_size, &dh_server_key) != 0) {
		return -1;
	}

	/* range check the value */
	ret = dh_range_check(&dh_ctx, &dh_server_key);
	if(ret == -1) {
		return -1;
	}
	if(ret == 1) {
		*res = INVALID_DH_KEY;
		return 1;
	}

	/* we're good.  calculate the secret */
	if(dh_compute_secret(&dh_ctx, &dh_priv_exp, &dh_server_key, &dh_secret) != 0) {
		return -1;
	}

	/* convert to octal string */
	dh_secret_size = dh_valwire_bufsize(&dh_secret);
	if((dh_secret_buf = malloc(dh_secret_size)) == NULL) {
		return -1;
	}

	if(dh_val2wire(&dh_secret, dh_secret_buf, dh_secret_size) != 0) {
		return -1;
	}

	/* create the keybuf */
	pbkdf2_hmac_sha256(dh_secret_buf, dh_secret_size, NULL, 0, 1, key_size, key_buf);

	/* free the buffer */
	zfree(dh_secret_buf, dh_secret_size);

	expand_keyset(key_buf, 0, keys);
	keys->nonce = 1;

	/* hash the keybuf */
	sha256(key_buf, 128, hash);

	ret = memcmp_ct(hash, &server_m->message[8 + rsa_sk_size + 8 + dh_sk_size],
		hlen);
	if(ret) {
		*res = INVALID_KEY_HASH;
		return 1;
	}

	/* now check if this server is who they say they are */
	/* check the size */
	if(rsa_sk_size > (16384 / 8)) return -1; /* this is unreasonable */

	/* expand the public key into the struct */
	if(rsa_wire2pubkey(rsa_sk, rsa_sk_size, server_rsa_key) != 0) {
		return -1;
	}

	sig_offset = 8 + rsa_sk_size + 8 + dh_sk_size + hlen;

	ret = 0;
	if(rsa_pss_verify(server_rsa_key,
		&server_m->message[sig_offset], server_m->length - sig_offset,
		&server_m->message[0], sig_offset, &ret) != 0) {
		return -1;
	}

	if(ret) {
		*res = INVALID_SIG;
	}

	ret = 0;
	/* cleanup */
	free_message(server_m); server_m = NULL;
	memsets(key_buf, 0, key_size);
	ret |= dh_free_ctx(&dh_ctx);
	ret |= dh_val_free(&dh_server_key);
	ret |= dh_val_free(&dh_public_key);
	ret |= dh_val_free(&dh_priv_exp);
	ret |= dh_val_free(&dh_secret);

	return *res ? 1 : 0;
}

