#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/rand.h>
#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/scrypt.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/endian.h>
#include <libibur/util.h>

#include "userfile.h"
#include "login.h"
#include "../util/user.h"

#define IO_CHECK(w, expected, errcode) do { if((w) != (expected)) { ret = (errcode); goto err; } } while(0)
#define W_CHECK(w, expected) IO_CHECK(w, expected, UF_WRITE_FAIL)
#define R_CHECK(r, expected) IO_CHECK(r, expected, UF_READ_FAIL)

#define WRITE(buf, len, file) do {               \
	W_CHECK(fwrite(buf, 1, len, file), len); \
} while(0)

#define READ(buf, len, file) do {                \
	R_CHECK(fread(buf, 1, len, file), len);  \
} while(0)

static uint8_t uf_magic[] = "ibclientuserfile";
static size_t uf_magic_len = 16;

int write_userfile(struct login_data *user, char *filename) {
	FILE *out = NULL;
	uint8_t uid[32];
	uint8_t mac1[32];
	uint8_t mac2[32];
	uint8_t salt[32];
	uint8_t sizebuf[8];
	uint8_t scrypt_out[96];
	uint8_t *pw_check = &scrypt_out[0x00];
	uint8_t *symm_key = &scrypt_out[0x20];
	uint8_t *hmac_key = &scrypt_out[0x40];
	uint8_t *payload = NULL;
	uint64_t size = 0;
	HMAC_SHA256_CTX ctx, tmp_ctx;

	int ret = 0;

	gen_uid(user->uname, strlen(user->uname), uid);

	if(cs_rand(salt, 32) != 0) {
		ret = UF_PROG_FAIL;
		goto err;
	}

	if(scrypt(user->pass, strlen(user->pass), salt, 32, (uint64_t)1 << 16,
		8, 1, 96, scrypt_out) != 0) {
		ret = UF_PROG_FAIL;
		goto err;
	}

	size = 32 + 32 + rsa_prikey_bufsize(user->id.bits);
	encbe64(size, sizebuf);

	if((payload = malloc(size)) == NULL) {
		ret = UF_MEM_FAIL;
		goto err;
	}

	memcpy(&payload[0x00], user->symm_seed, 0x20);
	memcpy(&payload[0x20], user->hmac_seed, 0x20);

	if(rsa_prikey2wire(&user->id, &payload[0x40], size - 0x40) != 0) {
		ret = UF_PROG_FAIL;
		goto err;
	}

	chacha_enc(symm_key, 32, 0, payload, payload, size);

	if((out = fopen(filename, "wb")) == NULL) {
		ret = UF_OPEN_FAIL;
		goto err;
	}

	hmac_sha256_init(&ctx, hmac_key, 32);

	WRITE(uf_magic, uf_magic_len, out);
	hmac_sha256_update(&ctx, uf_magic, uf_magic_len);
	WRITE(uid, 32, out);
	hmac_sha256_update(&ctx, uid, 32);
	WRITE(salt, 32, out);
	hmac_sha256_update(&ctx, salt, 32);
	WRITE(pw_check, 32, out);
	hmac_sha256_update(&ctx, pw_check, 32);
	WRITE(sizebuf, 8, out);
	hmac_sha256_update(&ctx, sizebuf, 8);

	tmp_ctx = ctx;
	hmac_sha256_final(&tmp_ctx, mac1);

	WRITE(mac1, 32, out);
	hmac_sha256_update(&ctx, mac1, 32);
	WRITE(payload, size, out);
	hmac_sha256_update(&ctx, payload, size);

	hmac_sha256_final(&ctx, mac2);
	WRITE(mac2, 32, out);

	if(fclose(out) != 0) {
		out = NULL;
		ret = UF_CLOSE_FAIL;
		goto err;
	}

err: /* most of the buffers don't need to be cleared as they aren't private */
	if(out) fclose(out);
	memsets(scrypt_out, 0, 96);
	if(payload) zfree(payload, size);

	return ret;
}

int read_userfile(struct login_data *user, char *filename) {
	FILE *in = NULL;
	uint8_t magic_buf[uf_magic_len];
	uint8_t uid[32];
	uint8_t uid_f[32];
	uint8_t mac1[32];
	uint8_t mac2[32];
	uint8_t mac1_f[32];
	uint8_t mac2_f[32];
	uint8_t salt[32];
	uint8_t sizebuf[8];
	uint8_t scrypt_out[96];
	uint8_t *pw_check = &scrypt_out[0x00];
	uint8_t *symm_key = &scrypt_out[0x20];
	uint8_t *hmac_key = &scrypt_out[0x40];
	uint8_t pw_check_f[32];
	uint8_t *payload = NULL;
	uint64_t size = 0;
	HMAC_SHA256_CTX ctx, tmp_ctx;

	int ret = 0;

	if((in = fopen(filename, "rb")) == NULL) {
		ret = UF_OPEN_FAIL;
		goto err;
	}

	READ(magic_buf, uf_magic_len, in);
	if(memcmp_ct(uf_magic, magic_buf, uf_magic_len) != 0) {
		ret = UF_INV_MAGIC;
		goto err;
	}

	gen_uid(user->uname, strlen(user->uname), uid);
	READ(uid_f, 32, in);
	if(memcmp_ct(uid_f, uid, 32) != 0) {
		ret = UF_INV_UID;
		goto err;
	}

	READ(salt, 32, in);

	if(scrypt(user->pass, strlen(user->pass), salt, 32, (uint64_t)1 << 16,
		8, 1, 96, scrypt_out) != 0) {
		ret = UF_PROG_FAIL;
		goto err;
	}

	READ(pw_check_f, 32, in);
	if(memcmp_ct(pw_check_f, pw_check, 32) != 0) {
		ret = UF_INV_PASS;
		goto err;
	}

	READ(sizebuf, 8, in);
	READ(mac1_f, 32, in);

	hmac_sha256_init(&ctx, hmac_key, 32);
	hmac_sha256_update(&ctx, uf_magic, uf_magic_len);
	hmac_sha256_update(&ctx, uid, 32);
	hmac_sha256_update(&ctx, salt, 32);
	hmac_sha256_update(&ctx, pw_check_f, 32);
	hmac_sha256_update(&ctx, sizebuf, 8);
	tmp_ctx = ctx;
	hmac_sha256_final(&tmp_ctx, mac1);

	if(memcmp_ct(mac1, mac1_f, 32) != 0) {
		ret = UF_INV_MAC;
		goto err;
	}

	size = decbe64(sizebuf);
	if((payload = malloc(size)) == NULL) {
		ret = UF_MEM_FAIL;
		goto err;
	}

	READ(payload, size, in);
	READ(mac2_f, 32, in);

	hmac_sha256_update(&ctx, mac1_f, 32);
	hmac_sha256_update(&ctx, payload, size);
	hmac_sha256_final(&ctx, mac2);

	if(memcmp_ct(mac2, mac2_f, 32) != 0) {
		ret = UF_INV_MAC;
		goto err;
	}

	chacha_dec(symm_key, 32, 0, payload, payload, size);

	memcpy(user->symm_seed, &payload[0x00], 0x20);
	memcpy(user->hmac_seed, &payload[0x20], 0x20);
	if(rsa_wire2prikey(&payload[0x40], size - 0x40, &user->id) != 0) {
		ret = UF_PROG_FAIL;
		goto err;
	}

	if(fclose(in) != 0) {
		in = NULL;
		ret = UF_CLOSE_FAIL;
		goto err;
	}

err:
	if(in) fclose(in);
	memsets(scrypt_out, 0, 96);
	memsets(mac1, 0, 32);
	memsets(mac2, 0, 32);
	memsets(uid, 0, 32);
	if(payload) zfree(payload, size);

	return ret;
}
