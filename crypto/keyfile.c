#include <stdio.h>
#include <stdint.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/zfree.h>

#include <libibur/endian.h>

#include "keyfile.h"

// TODO: include passwords

int write_pri_key(RSA_KEY *key, const char *filename) {
	size_t size = rsa_prikey_bufsize(key->bits);
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

	size_t written = fwrite(buf, 1, size, out);
	fclose(out);

	if(written != size) {
		ret = WRITE_FAIL;
		goto err;
	}

	return 0;

err:
	zfree(buf, size);

	return -1;
}

int write_pub_key(RSA_PUBLIC_KEY *key, const char *filename) {
	size_t size = rsa_pubkey_bufsize(key->bits);
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

	size_t written = fwrite(buf, 1, size, out);
	fclose(out);

	if(written != size) {
		ret = WRITE_FAIL;
		goto err;
	}

	return 0;

err:
	zfree(buf, size);

	return ret;
}

int read_pri_key(const char *filename, RSA_KEY *key) {
	uint8_t size_buf[8];
	uint8_t *buf = NULL;
	size_t size, read;
	FILE *in;

	int ret = 0;

	in = fopen(filename, "rb");
	if(in == NULL) {
		return OPEN_FAIL;
	}

	read = fread(size_buf, 1, 8, in);
	if(read != 8) {
		ret = READ_FAIL;
		goto err;
	}

	size = rsa_prikey_bufsize(decbe64(size_buf));

	buf = malloc(size);
	if(buf == NULL) {
		ret = MEM_FAIL;
		goto err;
	}

	memcpy(buf, size_buf, 8);

	read = fread(&buf[8], 1, size - 8, in);
	fclose(in);
	in = NULL;

	if(read != size - 8) {
		ret = READ_FAIL;
		goto err;
	}

	if(rsa_wire2prikey(buf, size, key) != 0) {
		ret = CRYPTOGRAPHY_FAIL;
		goto err;
	}

	return 0;

err:
	if(in)  fclose(in);
	if(buf) zfree(buf, size);

	return ret;
}

int read_pub_key(const char *filename, RSA_PUBLIC_KEY *key) {
	uint8_t size_buf[8];
	uint8_t *buf = NULL;
	size_t size, read;
	FILE *in;

	int ret = 0;

	in = fopen(filename, "rb");
	if(in == NULL) {
		return OPEN_FAIL;
	}

	read = fread(size_buf, 1, 8, in);
	if(read != 8) {
		ret = READ_FAIL;
		goto err;
	}

	size = rsa_pubkey_bufsize(decbe64(size_buf));

	buf = malloc(size);
	if(buf == NULL) {
		ret = MEM_FAIL;
		goto err;
	}

	memcpy(buf, size_buf, 8);

	read = fread(&buf[8], 1, size - 8, in);
	fclose(in);
	in = NULL;

	if(read != size - 8) {
		ret = READ_FAIL;
		goto err;
	}

	if(rsa_wire2pubkey(buf, size, key) != 0) {
		ret = CRYPTOGRAPHY_FAIL;
		goto err;
	}

	return 0;

err:
	if(in)  fclose(in);
	if(buf) zfree(buf, size);

	return ret;
}

