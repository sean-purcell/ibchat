#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>

#include <ibcrypt/bignum.h>
#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/zfree.h>

#include "line_prompt.h"
#include "../crypto/keyfile.h"

int gen_key(int argc, char **argv) {
	if(argc != 4 && argc != 5) {
		fprintf(stderr, "usage: %s %s <outfile (no extension)> <bits> [public exponent]\n",
			argv[0], argv[1]);
		return 1;
	}

	argc--; argv++;

	uint64_t bits = strtoull(argv[2], NULL, 0);
	uint64_t exp = 65537;

	if(argc == 4) {
		exp = strtoull(argv[3], NULL, 0);
	}

	if(bits & 1 || bits == 0 || bits > 1000000) {
		fprintf(stderr, "invalid keysize\n");
		return 1;
	}

	if(!(exp & 1) || exp == 1 || exp == ULLONG_MAX) {
		fprintf(stderr, "invalid public exponent\n");
		return 1;
	}

	fprintf(stderr, "generating %" PRIu64 " bit rsa key with a public exponent of"
	                " %" PRIu64 "\n", bits, exp);

	RSA_KEY key;
	RSA_PUBLIC_KEY pkey;
	char *filename = NULL;
	char *password = NULL;
	size_t fname_size;

	int ret;

	password = line_prompt(
		"Private key password (empty string for no pass)",
		"Confirm password",
		1);

	if(password == NULL) {
		ret = 10;
		goto err;
	}
	if(strcmp(password, "") == 0) {
		free(password);
		password = NULL;
	}

	if((ret = rsa_gen_key(&key, bits, exp)) != 0) {
		goto err;
	}

	if((ret = rsa_pub_key(&key, &pkey)) != 0) {
		goto err;
	}

	fprintf(stderr, "key generated\n");

	fname_size = strlen(argv[1]);

	filename = malloc(fname_size + 5);
	if(filename == NULL) {
		errno = ENOMEM;
		goto err;
	}

	memcpy(filename, argv[1], fname_size);

	memcpy(&filename[fname_size], ".pri", 5);
	ret = write_pri_key(&key, filename, password);
	if(ret != 0) {
		goto err;
	}

	memcpy(&filename[fname_size], ".pub", 5);
	ret = write_pub_key(&pkey, filename);
	if(ret != 0) {
		goto err;
	}

	fprintf(stderr, "private key written to %s.pri\n"
	        "public key written to %s.pub\n", argv[1], argv[1]);

	free(filename);

	rsa_free_pubkey(&pkey);
	rsa_free_prikey(&key);

	if(password) zfree(password, strlen(password));

	return 0;

err:;
	char *estr = NULL;
	switch(ret) {
	case MEM_FAIL:
		estr = "failed to allocate memory\n"; break;
	case CRYPTOGRAPHY_FAIL:
		estr = "a cryptography error occurred\n"; break;
	case OPEN_FAIL:
		estr = "failed to open file\n"; break;
	case WRITE_FAIL:
		estr = "failed to write to file\n"; break;
	case 10:
		estr = "failed to read password\n"; break;
	}
	fprintf(stderr, "%s", estr);

	rsa_free_pubkey(&pkey);
	rsa_free_prikey(&key);

	if(password) zfree(password, strlen(password));

	return 1;
}

