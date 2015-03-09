#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>

#include <libibur/util.h>

#include "../crypto/handshake.h"
#include "../crypto/crypto_layer.h"
#include "../inet/connect.h"

#define PORT "35931"

int main(int argc, char **argv) {
	if(argc != 2) {
		fprintf(stderr, "usage: %s <address>\n", argv[0]);
		return 1;
	}

	struct sock server;

	server = client_connect(argv[1], PORT);
	if(server.fd == -1) {
		if(errno == 0) {
			fprintf(stderr, "getaddrinfo failed\n");
		} else {
			perror("connect error");
		}

		return 1;
	}

	printf("connected to %s\n", server.address);

	/* initiate handshake */
	struct con_handle handler;
	struct keyset keys;
	RSA_PUBLIC_KEY server_key;
	uint8_t *server_key_buf;
	uint64_t server_key_bufsize;
	int res;
	int ret;

	init_handler(&handler, server.fd);

	ret = client_handshake(&handler, &server_key, &keys, &res);
	if(ret == -1) {
		fprintf(stderr, "handshake programmatic error\n");
		goto ehandshake;
	} else if(ret == 1) {
		switch(res) {
		case INVALID_SIG:
			fprintf(stderr,
				"server provided invalid signature\n");
			break;
		case INVALID_DH_KEY:
			fprintf(stderr,
				"server provided invalid DH key\n");
			break;
		case INVALID_KEY_HASH:
			fprintf(stderr,
				"server provided invalid key hash\n");
			break;
		}

		goto ehandshake;
	}

	/* connected */
	server_key_bufsize = rsa_pubkey_bufsize(server_key.bits);
	server_key_buf = malloc(server_key_bufsize);
	if(server_key_buf == NULL) {
		fprintf(stderr,
			"failed to allocate memory\n");
		goto eprint;
	}
	if(rsa_pubkey2wire(&server_key, server_key_buf, server_key_bufsize) != 0) {
		fprintf(stderr,
			"failed to convert to wire format\n");
		goto eprint;
	}
	printf("public key:\n");
	printbuf(server_key_buf, server_key_bufsize);
	printf("symmetric keys:\n");
	printbuf(keys.send_symm_key, 32);
	printbuf(keys.recv_symm_key, 32);
	printbuf(keys.send_hmac_key, 32);
	printbuf(keys.recv_hmac_key, 32);
	/* done */
	if(rsa_free_pubkey(&server_key) != 0) {
		fprintf(stderr,
			"failed to free public key\n");
		goto efree;
	}
	memset(&keys, 0, sizeof(struct keyset));
	free(server_key_buf);

	end_handler(&handler);
	destroy_handler(&handler);

	return 0;

efree:
eprint:
	free(server_key_buf);
	rsa_free_pubkey(&server_key);
ehandshake:
	end_handler(&handler);
	destroy_handler(&handler);

	return 1;
}

