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

#define HANDSHAKE_DEBUG

#ifdef HANDSHAKE_DEBUG
# define HS_TRACE() do { fprintf(stderr, "ERROR: %d\n", __LINE__); } while(0);
#else
# define HS_TRACE() do { } while(0);
#endif

int server_handshake(struct con_handle *con, RSA_KEY *rsa_key, struct keyset *keys) {
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

	RSA_PUBLIC_KEY rsa_pkey;

	DH_CTX dh_ctx;
	DH_PUB dh_client_key = DH_VAL_INIT;
	DH_PUB dh_public_key = DH_VAL_INIT;
	DH_PRI dh_priv_exp = DH_VAL_INIT;
	DH_VAL dh_secret = DH_VAL_INIT;

	uint8_t *dh_secret_buf;
	uint64_t dh_secret_size;

	uint8_t *response;
	uint64_t response_size;
	uint64_t rsa_key_off;
	uint64_t rsa_key_size;
	uint64_t dh_key_off;
	uint64_t dh_key_size;
	uint64_t hash_off;
	uint64_t sig_off;
	uint64_t sig_size;

	int ret;

	gettimeofday(&tv, NULL);
	start = utime(tv);

	/* create a public key from our private key */
	if(rsa_pub_key(rsa_key, &rsa_pkey) != 0) {
		HS_TRACE();
		return -1;
	}

	if(dh_init_ctx(&dh_ctx, 14) != 0) {
		HS_TRACE();
		return -1;
	}
	if(dh_gen_exp(&dh_ctx, &dh_priv_exp) != 0) {
		HS_TRACE();
		return -1;
	}
	if(dh_gen_pub(&dh_ctx, &dh_priv_exp, &dh_public_key) != 0) {
		HS_TRACE();
		return -1;
	}

	/* wait for the client message */
	gettimeofday(&tv, NULL);
	client_m = get_message(con, total_time - (utime(tv) - start));
	if(client_m == NULL) {
		HS_TRACE();
		return -1;
	}

	/* expand the response */
	if(dh_wire2val(client_m->message, client_m->length, &dh_client_key) != 0) {
		HS_TRACE();
		return -1;
	}

	/* range check the value */
	ret = dh_range_check(&dh_ctx, &dh_client_key);
	if(ret == -1) {
		HS_TRACE();
		return -1;
	}
	if(ret == 0) {
		HS_TRACE();
		return INVALID_DH_KEY;
	}

	/* calculate the secret */
	if(dh_compute_secret(&dh_ctx, &dh_priv_exp, &dh_client_key, &dh_secret) != 0) {
		HS_TRACE();
		return -1;
	}

	/* convert to octal string */
	dh_secret_size = dh_valwire_bufsize(&dh_secret);
	if((dh_secret_buf = malloc(dh_secret_size)) == NULL) {
		HS_TRACE();
		return -1;
	}

	if(dh_val2wire(&dh_secret, dh_secret_buf, dh_secret_size) != 0) {
		HS_TRACE();
		return -1;
	}

	/* create the keybuf */
	pbkdf2_hmac_sha256(dh_secret_buf, dh_secret_size, NULL, 0, 1, key_size, key_buf);

	/* free the buffer */
	zfree(dh_secret_buf, dh_secret_size);

	expand_keyset(key_buf, 1, keys);
	keys->nonce = 1;

	/* hash the keybuf */
	sha256(key_buf, 128, hash);

	/* now we build our response */
	rsa_key_size = 8 + rsa_pubkey_bufsize(rsa_pkey.bits);
	dh_key_size  = 8 + dh_valwire_bufsize(&dh_public_key);
	sig_size = (rsa_pkey.bits + 7) / 8;
	response_size = rsa_key_size + dh_key_size + hlen + sig_size;

	server_m = alloc_message(response_size);
	if(server_m == NULL) {
		HS_TRACE();
		return -1;
	}

	response = server_m->message;

	rsa_key_off = 0;
	dh_key_off = rsa_key_size;
	hash_off = dh_key_off + dh_key_size;
	sig_off = hash_off + hlen;

	encbe64(rsa_key_size - 8, &response[rsa_key_off]);
	if(rsa_pubkey2wire(&rsa_pkey, &response[rsa_key_off + 8], rsa_key_size - 8) != 0) {
		HS_TRACE();
		return -1;
	}

	encbe64(dh_key_size - 8, &response[dh_key_off]);
	if(dh_val2wire(&dh_public_key, &response[dh_key_off + 8], dh_key_size - 8) != 0) {
		HS_TRACE();
		return -1;
	}

	memcpy(&response[hash_off], hash, hlen);

	if((ret = rsa_pss_sign(rsa_key, response, sig_off, &response[sig_off], sig_size)) != 0) {
		HS_TRACE();
#ifdef HANDSHAKE_DEBUG
		fprintf(stderr, "rsa_pss_sign ret:%d\n", ret);
#endif
		return -1;
	}

	server_m->seq_num = 0;
	/* message constructed, fire away */
	add_message(con, server_m);
	server_m = NULL;

	/* cleanup */
	ret = 0;

	free_message(client_m); client_m = NULL;
	memsets(key_buf, 0, key_size);
	ret |= dh_free_ctx(&dh_ctx);
	ret |= dh_val_free(&dh_client_key);
	ret |= dh_val_free(&dh_public_key);
	ret |= dh_val_free(&dh_priv_exp);
	ret |= dh_val_free(&dh_secret);

	if(ret) {
		HS_TRACE();
		return -1;
	}

	return 0;
}

/* res indicates the results.  it is 0 if everything worked out fine, other
 * values are defined in the header
 * program failures have a return value of -1,
 * invalid states have a positive return value */
int client_handshake(struct con_handle *con, RSA_PUBLIC_KEY *server_rsa_key, struct keyset *keys, int *res) {
	/* measure our starting time, we allow maximum 5 seconds for this */
	struct timeval tv;
	uint64_t start;

	const uint64_t total_time = 10000000ULL;

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
		HS_TRACE();
		return -1;
	}
	if(dh_gen_exp(&dh_ctx, &dh_priv_exp) != 0) {
		HS_TRACE();
		return -1;
	}
	if(dh_gen_pub(&dh_ctx, &dh_priv_exp, &dh_public_key) != 0) {
		HS_TRACE();
		return -1;
	}

	/* send the public key message */
	client_m = alloc_message(dh_valwire_bufsize(&dh_public_key));
	if(client_m == NULL) {
		HS_TRACE();
		return -1;
	}

	if(dh_val2wire(&dh_public_key, client_m->message, client_m->length) != 0) {
		HS_TRACE();
		return -1;
	}

	client_m->seq_num = 0;

	add_message(con, client_m);
	client_m = NULL;

	/* wait for the response */
	gettimeofday(&tv, NULL);
	server_m = get_message(con, total_time - (utime(tv) - start));
	if(server_m == NULL) {
		HS_TRACE();
		return -1;
	}

	rsa_sk = &server_m->message[8];
	rsa_sk_size = decbe64(&server_m->message[0]);

	/* message size sanity checks */
	if(8 + rsa_sk_size + 8 > server_m->length) {
		HS_TRACE();
		return -1;
	}

	dh_sk = &server_m->message[16 + rsa_sk_size];
	dh_sk_size = decbe64(&server_m->message[8 + rsa_sk_size]);

	if(8 + rsa_sk_size + 8 + dh_sk_size > server_m->length) {
		HS_TRACE();
		return -1;
	}

	if(dh_sk_size > (dh_ctx.bits + 7) / 8 + 8) {
		*res = INVALID_DH_KEY;
		HS_TRACE();
		return 1;
	}

	if(dh_wire2val(dh_sk, dh_sk_size, &dh_server_key) != 0) {
		HS_TRACE();
		return -1;
	}

	/* range check the value */
	ret = dh_range_check(&dh_ctx, &dh_server_key);
	if(ret == -1) {
		HS_TRACE();
		return -1;
	}
	if(ret == 0) {
		*res = INVALID_DH_KEY;
		HS_TRACE();
		return 1;
	}

	/* we're good.  calculate the secret */
	if(dh_compute_secret(&dh_ctx, &dh_priv_exp, &dh_server_key, &dh_secret) != 0) {
		HS_TRACE();
		return -1;
	}

	/* convert to octal string */
	dh_secret_size = dh_valwire_bufsize(&dh_secret);
	if((dh_secret_buf = malloc(dh_secret_size)) == NULL) {
		HS_TRACE();
		return -1;
	}

	if(dh_val2wire(&dh_secret, dh_secret_buf, dh_secret_size) != 0) {
		HS_TRACE();
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

	/* compare to the included hash, with a sanity check first */
	if(8 + rsa_sk_size + 8 + dh_sk_size + hlen > server_m->length) {
		HS_TRACE();
		return -1;
	}
	ret = memcmp_ct(hash, &server_m->message[8 + rsa_sk_size + 8 + dh_sk_size],
		hlen);
	if(ret) {
		*res = INVALID_KEY_HASH;
		HS_TRACE();
		return 1;
	}

	/* now check if this server is who they say they are */
	/* check the size */
	if(rsa_sk_size > (16384 / 8)) {
		HS_TRACE();
		return -1; /* this is unreasonable */
	}

	/* expand the public key into the struct */
	if(rsa_wire2pubkey(rsa_sk, rsa_sk_size, server_rsa_key) != 0) {
		HS_TRACE();
		return -1;
	}

	sig_offset = 8 + rsa_sk_size + 8 + dh_sk_size + hlen;

	ret = 0;
	if(rsa_pss_verify(server_rsa_key,
		&server_m->message[sig_offset], server_m->length - sig_offset,
		&server_m->message[0], sig_offset, &ret) != 0) {
		HS_TRACE();
		return -1;
	}

	if(ret == 0) {
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

	if(ret) {
		HS_TRACE();
		return -1;
	}

	return *res ? 1 : 0;
}

