#include <stdio.h>
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

#include "keyfile.h"
#include "../util/getpass.h"

#define IO_CHECK(w, expected, errcode) do { if((w) != (expected)) { ret = (errcode); goto err; } } while(0)
#define W_CHECK(w, expected) IO_CHECK(w, expected, WRITE_FAIL)
#define R_CHECK(r, expected) IO_CHECK(r, expected, READ_FAIL)

#define WRITE(buf, len, file) do {               \
	W_CHECK(fwrite(buf, 1, len, file), len); \
} while(0)

#define READ(buf, len, file) do {                \
	R_CHECK(fread(buf, 1, len, file), len);  \
} while(0)

static const char *magic = "ibrsakey";
static const size_t magic_len = 8;

static int write_pri_key_password(uint8_t *key, uint64_t key_size, FILE *out, char *password);
int write_pri_key(RSA_KEY *key, const char *filename, char *password) {
	uint64_t size = rsa_prikey_bufsize(key->bits);
	uint8_t numbuf[8];
	uint8_t typebuf[8];
	uint8_t *buf;
	FILE *out;

	int ret = 0;

	buf = malloc(size);
	if(buf == NULL) {
		return MEM_FAIL;
	}

	if(rsa_prikey2wire(key, buf, size) != 0) {
		ret = CRYPTOGRAPHY_FAIL;
		goto err;
	}

	out = fopen(filename, "wb");
	if(out == NULL) {
		ret = OPEN_FAIL;
		goto err;
	}

	WRITE(magic, magic_len, out);

	encbe64(2, numbuf);
	WRITE(numbuf, 8, out);

	encbe64(password ? 2 : 1, typebuf);
	WRITE(typebuf, 8, out);

	if(password) {
		ret = write_pri_key_password(buf, size, out, password);
		if(ret) goto err;
	} else {
		WRITE(buf, size, out);
	}

	ret = 0;

err:
	fclose(out);
	zfree(buf, size);

	return ret;
}

static int write_pri_key_password(uint8_t *key, uint64_t key_size, FILE *out, char *password) {
	uint8_t salt[32];
	uint8_t keybuf[64];
	uint8_t macbuf[32];
	uint8_t sizebuf[8];
	uint8_t *enc_key = &keybuf[ 0];
	uint8_t *mac_key = &keybuf[32];

	int ret;

	if(cs_rand(salt, 32) != 0) {
		ret = CRYPTOGRAPHY_FAIL;
		goto err;
	}

	if(scrypt(password, strlen(password), salt, 32, (uint64_t)1 << 16,
		8, 1, 64, keybuf) != 0) {
		ret = CRYPTOGRAPHY_FAIL;
		goto err;
	}

	if(chacha_enc(enc_key, 32, 0, key, key, key_size) != 0) {
		ret = CRYPTOGRAPHY_FAIL;
		goto err;
	}

	hmac_sha256(mac_key, 32, key, key_size, macbuf);

	encbe64(key_size, sizebuf);

	WRITE(sizebuf, 8, out);
	WRITE(salt, 32, out);
	WRITE(key, key_size, out);
	WRITE(macbuf, 32, out);

	ret = 0;

err:
	memsets(salt, 0, 32);
	memsets(keybuf, 0, 64);
	memsets(macbuf, 0, 32);
	memsets(sizebuf, 0, 8);

	return ret;
}

int write_pub_key(RSA_PUBLIC_KEY *key, const char *filename) {
	size_t size = rsa_pubkey_bufsize(key->bits);
	uint8_t numbuf[8];
	uint8_t *buf;
	FILE *out;

	int ret = 0;

	buf = malloc(size);
	if(buf == NULL) {
		return MEM_FAIL;
	}

	if(rsa_pubkey2wire(key, buf, size) != 0) {
		ret = CRYPTOGRAPHY_FAIL;
		goto err;
	}

	out = fopen(filename, "wb");
	if(out == NULL) {
		ret = OPEN_FAIL;
		goto err;
	}

	WRITE(magic, magic_len, out);

	encbe64(1, numbuf);
	WRITE(numbuf, 8, out);

	WRITE(buf, size, out);

	ret = 0;
err:
	fclose(out);
	zfree(buf, size);

	return ret;
}

static int read_pri_key_nopassword(RSA_KEY *key, uint8_t **buf, uint64_t *bufsize, FILE *in);
static int read_pri_key_password(RSA_KEY *key, uint8_t **buf, uint64_t *bufsize, FILE *in, char *password);
int read_pri_key(const char *filename, RSA_KEY *key, char *password) {
	uint8_t magic_buf[magic_len];
	uint8_t num_buf[8];
	uint8_t size_buf[8];
	uint8_t *buf = NULL;
	uint64_t bufsize;
	FILE *in = NULL;

	int ret = 0;

	in = fopen(filename, "rb");
	if(in == NULL) {
		return OPEN_FAIL;
	}

	READ(magic_buf, magic_len, in);
	if(memcmp(magic_buf, magic, magic_len) != 0) {
		ret = INVALID_FILE;
		goto err;
	}

	READ(num_buf, 8, in);
	if(decbe64(num_buf) != 2) {
		ret = INVALID_FILE;
		goto err;
	}

	READ(num_buf, 8, in);
	switch(decbe64(num_buf)) {
	case 1:
		/* not password protected */
		ret = read_pri_key_nopassword(key, &buf, &bufsize, in);
		break;
	case 2:
		/* password protected */
		ret = read_pri_key_password(key, &buf, &bufsize, in, password);
		break;
	default:
		ret = INVALID_FILE;
		break;
	}

	if(ret) {
		goto err;
	}

	if(rsa_wire2prikey(buf, bufsize, key) != 0) {
		ret = CRYPTOGRAPHY_FAIL;
		goto err;
	}

	ret = 0;

err:
	if(in)  fclose(in);
	if(buf) zfree(buf, bufsize);

	return ret;
}

static int read_pri_key_nopassword(RSA_KEY *key, uint8_t **buf, uint64_t *bufsize, FILE *in) {
	uint8_t size_buf[8];
	uint64_t size;

	int ret;

	*buf = NULL;
	*bufsize = 0;

	READ(size_buf, 8, in);

	key->bits = decbe64(size_buf);
	size = rsa_prikey_bufsize(key->bits);

	*buf = malloc(size);
	if(*buf == NULL) {
		ret = MEM_FAIL;
		goto err;
	}

	*bufsize = size;

	memcpy(*buf, size_buf, 8);

	READ(&(*buf)[8], size - 8, in);

	ret = 0;

err:
	return ret;
}

static int read_pri_key_password(RSA_KEY *key, uint8_t **buf, uint64_t *bufsize, FILE *in, char *password) {
	int pass_prompted = 0;
	if(!password) {
		/* prompt for the password */
		password = ibchat_getpass("Private key encryption password", NULL, 1);
		pass_prompted = 1;
	}

	uint8_t salt[32];
	uint8_t keybuf[64];
	uint8_t macbuf1[32];
	uint8_t macbuf2[32];
	uint8_t sizebuf[8];
	uint64_t size;
	uint8_t *enc_key = &keybuf[ 0];
	uint8_t *mac_key = &keybuf[32];

	int ret;

	*buf = NULL;
	*bufsize = 0;

	READ(sizebuf, 8, in);
	size = decbe64(sizebuf);

	READ(salt, 32, in);

	*buf = malloc(size);
	if(*buf == NULL) {
		ret = MEM_FAIL;
		goto err;
	}

	*bufsize = size;

	if(scrypt(password, strlen(password), salt, 32, (uint64_t)1 << 16,
		8, 1, 64, keybuf) != 0) {
		ret = CRYPTOGRAPHY_FAIL;
		goto err;
	}

	READ(*buf, size, in);

	/* now check the mac */
	READ(macbuf1, 32, in);

	hmac_sha256(mac_key, 32, *buf, size, macbuf2);

	if(memcmp_ct(macbuf1, macbuf2, 32) != 0) {
		ret = INVALID_MAC;
		goto err;
	}

	if(chacha_dec(enc_key, 32, 0, *buf, *buf, size) != 0) {
		ret = CRYPTOGRAPHY_FAIL;
		goto err;
	}

	ret = 0;

err:
	memsets(salt, 0, 32);
	memsets(keybuf, 0, 64);
	memsets(macbuf1, 0, 32);
	memsets(macbuf2, 0, 32);

	if(pass_prompted) {
		zfree(password, strlen(password));
	}

	return ret;
}

int read_pub_key(const char *filename, RSA_PUBLIC_KEY *key) {
	uint8_t magic_buf[magic_len];
	uint8_t num_buf[8];
	uint8_t size_buf[8];
	uint8_t *buf = NULL;
	uint64_t bufsize;
	FILE *in = NULL;

	int ret = 0;

	in = fopen(filename, "rb");
	if(in == NULL) {
		return OPEN_FAIL;
	}

	READ(magic_buf, magic_len, in);
	if(memcmp(magic_buf, magic, magic_len) != 0) {
		ret = INVALID_FILE;
		goto err;
	}

	READ(num_buf, 8, in);
	if(decbe64(num_buf) != 1) {
		ret = INVALID_FILE;
		goto err;
	}

	READ(size_buf, 8, in);
	key->bits = decbe64(size_buf);
	bufsize = rsa_pubkey_bufsize(key->bits);

	buf = malloc(bufsize);
	if(buf == NULL) {
		ret = MEM_FAIL;
		goto err;
	}

	memcpy(buf, size_buf, 8);
	READ(&buf[8], bufsize - 8, in);

	if(rsa_wire2pubkey(buf, bufsize, key) != 0) {
		ret = CRYPTOGRAPHY_FAIL;
		goto err;
	}

	ret = 0;

err:
	if(in)  fclose(in);
	if(buf) zfree(buf, bufsize);

	return ret;
}

