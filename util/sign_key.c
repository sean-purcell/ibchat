#include <stdlib.h>
#include <stdio.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>

int sign_key(int argc, char **argv) {
	if(argc != 4) {
		fprintf(stderr, "usage: %s %s <private key file> <public key file> <outfile>",
			argv[0], argv[1]);
		return 1;
	}

	argc--; argv++;

	RSA_KEY root_key;
	RSA_PUBLIC_KEY root_pub_key;
	RSA_PUBLIC_KEY pub_key;

	int ret;

	return 0;
}

