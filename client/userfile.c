#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/scrypt.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include "userfile.h"

#define IO_CHECK(w, expected, errcode) do { if((w) != (expected)) { ret = (errcode); goto err; } } while(0)
#define W_CHECK(w, expected) IO_CHECK(w, expected, UF_WRITE_FAIL)
#define R_CHECK(r, expected) IO_CHECK(r, expected, UF_READ_FAIL)

#define WRITE(buf, len, file) do {               \
	W_CHECK(fwrite(buf, 1, len, file), len); \
} while(0)

#define READ(buf, len, file) do {                \
	R_CHECK(fread(buf, 1, len, file), len);  \
} while(0)

static char *uf_magic = "ibclientuserfile";
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

	memcpy(&payload[0x00], user->symm_seed, 32);
	memcpy(&payload[0x20], user->hmac_seed, 32);

	if(rsa_prikey2wire(&user->id, &payload[0x40], size - 0x40) != 0) {
		ret = UF_PROG_FAIL;
		goto err;
	}

	if(

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
	hmac_sha256_update(pw_check, 32);
	WRITE(size, 8, out);
	hmac_sha256_update(size, 8);

	tmp_ctx = ctx;
	hmac_sha256_final(&tmp_ctx, mac1);

	WRITE(mac1, 32, out);
	hmac_sha256_update(mac1, 32);
}

int read_userfile(struct login_data *user, char *password, char *filename) {

}

