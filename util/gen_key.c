#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/bignum.h>

int main(int argc, char **argv) {
	if(argc != 3 && argc != 4) {
		fprintf(stderr, "usage: %s <outfile (no extension)> <bits> [public exponent]\n", argv[0]);
		return 1;
	}

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

	fprintf(stderr, "generating %llu bit rsa key with a public exponent of"
	                " %llu\n", bits, exp);

	RSA_KEY key;
	RSA_PUBLIC_KEY pkey;
	uint8_t *key_bin = NULL;
	uint8_t *pkey_bin = NULL;
	FILE *key_out;
	FILE *pkey_out;
	char *filename = NULL;
	size_t written;
	size_t total;

	int ret;
	int e = 0;

	if((ret = rsa_gen_key(&key, bits, exp)) != 0) {
		goto egen;
	}

	if((ret = rsa_pub_key(&key, &pkey)) != 0) {
		goto epub;
	}

	fprintf(stderr, "key generated\n");

	key_bin = malloc(rsa_prikey_bufsize(bits));
	pkey_bin = malloc(rsa_pubkey_bufsize(bits));

	if(key_bin == NULL || pkey_bin == NULL) {
		errno = ENOMEM;
		goto emalloc;
	}

	if(rsa_prikey2wire(&key, key_bin, rsa_prikey_bufsize(bits)) != 0) {
		goto econvert;
	}

	if(rsa_pubkey2wire(&pkey, pkey_bin, rsa_pubkey_bufsize(bits)) != 0) {
		goto econvert;
	}

	filename = malloc(strlen(argv[1]) + 4);
	if(filename == NULL) {
		errno = ENOMEM;
		goto efname;
	}

	if(strcmp(argv[1], "--") == 0) {
		key_out = stdout;
		pkey_out = NULL;
	} else {
		memcpy(filename, argv[1], strlen(argv[1]));
		memcpy(&filename[strlen(argv[1])], ".pri", 5);
		key_out = fopen(filename, "wb");
		if(key_out == NULL) {
			goto eopri;
		}

		memcpy(&filename[strlen(argv[1])], ".pub", 5);
		pkey_out = fopen(filename, "wb");
		if(pkey_out == NULL) {
			goto eopub;
		}
	}

	total = rsa_prikey_bufsize(bits);
	written = fwrite(key_bin, 1, total, key_out);
	if(written != total) {
		goto ewrite;
	}

	if(pkey_out != NULL) {
		total = rsa_pubkey_bufsize(bits);
		written = fwrite(pkey_bin, 1, total, pkey_out);
		if(written != total) {
			goto ewrite;
		}
	}

	fprintf(stderr, "private key written to %s.pri\n"
	        "public key written to %s.pub\n", argv[1], argv[1]);

	fclose(key_out);
	if(!pkey_out) fclose(pkey_out);

	free(key_bin);
	free(pkey_bin);
	free(filename);

	memset(&key, 0, sizeof(RSA_KEY));
	memset(&pkey, 0, sizeof(RSA_PUBLIC_KEY));

	return 0;

ewrite:
	if(!e) fprintf(stderr, "error writing files\n");
	e = 1;
eopub:
	fclose(key_out);
eopri:
	free(filename);
	if(!e) fprintf(stderr, "error opening files\n");
	e = 1;
efname:
	if(!e) fprintf(stderr, "error allocating memory\n");
	e = 1;
econvert:
	free(pkey_bin);
	free(key_bin);
	if(!e) fprintf(stderr, "error converting to wire format\n");
	e = 1;
emalloc:
	if(!e) fprintf(stderr, "error allocating memory\n");
	e = 1;
epub:
egen:
	if(!e) fprintf(stderr, "cryptography error\n");
	e = 1;
	memset(&key, 0, sizeof(RSA_KEY));
	memset(&pkey, 0, sizeof(RSA_PUBLIC_KEY));

	return 1;
}

