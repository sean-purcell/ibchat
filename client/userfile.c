#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

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
#include "account.h"
#include "profile.h"
#include "uname.h"
#include "ibchat_client.h"

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

static const char *UFILE_SUFFIX = "ufile.ibc";
static char *UFILE_PATH = NULL;

static int init_acc_file_str() {
	if(UFILE_PATH != NULL) {
		return 0;
	}
	UFILE_PATH = malloc(strlen(ROOT_DIR) + strlen(UFILE_SUFFIX) + 1);
	if(UFILE_PATH == NULL) {
		return -1;
	}

	strcpy(UFILE_PATH, ROOT_DIR);
	strcpy(&UFILE_PATH[strlen(ROOT_DIR)], UFILE_SUFFIX);
	UFILE_PATH[strlen(ROOT_DIR) + strlen(UFILE_SUFFIX)] = '\0';

	return 0;
}

int user_exist() {
	if(init_acc_file_str() != 0) {
		return -1;
	}

	/* check if theres a file at the expected address */
	FILE* afile = fopen(UFILE_PATH, "rb");
	if(afile == NULL) {
		if(errno == ENOENT) {
			return 0;
		} else {
			return -1;
		}
	}
	fclose(afile);

	return 1;
}

int write_userfile(struct profile *user) {
	if(init_acc_file_str() != 0) {
		return -1;
	}
	FILE *out = NULL;
	uint8_t mac1[32];
	uint8_t mac2[32];
	uint8_t sizebuf[8];
	uint8_t noncebuf[8];
	uint8_t *payload = NULL;
	uint64_t size = 0, num_acc = 0;
	uint8_t *payload_ptr;
	HMAC_SHA256_CTX ctx, tmp_ctx;
	struct account *accounts;

	int ret = 0;

	size = 8;
	num_acc = 0;
	accounts = user->server_accounts;
	while(accounts != NULL) {
		size += account_bin_size(accounts);
		num_acc++;
		accounts = accounts->next;
	}

	encbe64(size, sizebuf);
	encbe64(user->nonce, noncebuf);

	if((payload = malloc(size)) == NULL) {
		ret = UF_MEM_FAIL;
		goto err;
	}

	encbe64(num_acc, payload);
	payload_ptr = &payload[8];
	accounts = user->server_accounts;
	while(accounts != NULL) {
		payload_ptr = account_write_bin(accounts, payload_ptr);
		accounts = accounts->next;
	}

	if(payload_ptr != (payload + size)) {
		ret = UF_PROG_FAIL;
		goto err;
	}

	/* it is the responsibility of the caller to handle the nonce properly */
	chacha_enc(user->symm_key, 32, user->nonce, payload, payload, size);

	if((out = fopen(UFILE_PATH, "wb")) == NULL) {
		ret = UF_OPEN_FAIL;
		goto err;
	}

	hmac_sha256_init(&ctx, user->hmac_key, 32);

	WRITE(uf_magic, uf_magic_len, out);
	hmac_sha256_update(&ctx, uf_magic, uf_magic_len);
	WRITE(user->salt, 32, out);
	hmac_sha256_update(&ctx, user->salt, 32);
	WRITE(user->pw_check, 32, out);
	hmac_sha256_update(&ctx, user->pw_check, 32);
	WRITE(sizebuf, 8, out);
	hmac_sha256_update(&ctx, sizebuf, 8);
	WRITE(noncebuf, 8, out);
	hmac_sha256_update(&ctx, noncebuf, 8);

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

	out = NULL;

err: /* most of the buffers don't need to be cleared as they aren't private */
	if(out) fclose(out);
	if(payload) zfree(payload, size);

	return ret;
}

int read_userfile(struct profile *user) {
	if(init_acc_file_str() != 0) {
		return -1;
	}
	FILE *in = NULL;
	uint8_t magic_buf[uf_magic_len];
	uint8_t mac1[32];
	uint8_t mac2[32];
	uint8_t mac1_f[32];
	uint8_t mac2_f[32];
	uint8_t salt[32];
	uint8_t sizebuf[8];
	uint8_t noncebuf[8];
	uint8_t scrypt_out[96];
	uint8_t *pw_check = &scrypt_out[0x00];
	uint8_t *symm_key = &scrypt_out[0x20];
	uint8_t *hmac_key = &scrypt_out[0x40];
	uint8_t pw_check_f[32];
	uint8_t *payload = NULL, *payload_ptr;
	uint64_t size = 0, num_acc, idx;
	HMAC_SHA256_CTX ctx, tmp_ctx;
	struct account **accounts;

	int ret = 0;

	if((in = fopen(UFILE_PATH, "rb")) == NULL) {
		ret = UF_OPEN_FAIL;
		goto err;
	}

	READ(magic_buf, uf_magic_len, in);
	if(memcmp_ct(uf_magic, magic_buf, uf_magic_len) != 0) {
		ret = UF_INV_MAGIC;
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
	READ(noncebuf, 8, in);
	READ(mac1_f, 32, in);

	hmac_sha256_init(&ctx, hmac_key, 32);
	hmac_sha256_update(&ctx, uf_magic, uf_magic_len);
	hmac_sha256_update(&ctx, salt, 32);
	hmac_sha256_update(&ctx, pw_check_f, 32);
	hmac_sha256_update(&ctx, sizebuf, 8);
	hmac_sha256_update(&ctx, noncebuf, 8);
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

	user->nonce = decbe64(noncebuf);
	chacha_dec(symm_key, 32, user->nonce, payload, payload, size);

	num_acc = decbe64(payload);
	accounts = &user->server_accounts;
	payload_ptr = &payload[8];
	for(idx = 0; idx < num_acc; idx++) {
		payload_ptr = account_parse_bin(accounts, payload_ptr);
		if(payload_ptr == NULL) {
			ret = UF_PROG_FAIL;
			goto err;
		}
		accounts = &((*accounts)->next);
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
	if(payload) zfree(payload, size);

	return ret;
}

