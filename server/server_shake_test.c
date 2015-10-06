#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>

#include <libibur/util.h>

#include "../crypto/handshake.h"
#include "../crypto/crypto_layer.h"
#include "../crypto/keyfile.h"
#include "../inet/connect.h"

#define PORT "35931"

int main(int argc, char **argv) {
	signal(SIGPIPE, SIG_IGN);
	if(argc != 2) {
		fprintf(stderr, "usage: %s <private key file>\n", argv[0]);
		return 1;
	}

	struct sock server;
	struct sock client;

	server = server_bind(PORT);
	if(server.fd < 0) {
		if(server.fd == -2) {
			fprintf(stderr, "getaddrinfo failed\n");
		} else {
			perror("bind error");
		}

		return 1;
	}

	printf("server opened on local ip %s\n", server.address);

	client = server_accept(server.fd);
	if(client.fd == -1) {
		perror("accept error");

		return 1;
	}

	printf("client connected from %s\n", client.address);

	RSA_KEY private_key;
	RSA_PUBLIC_KEY server_key;
	struct con_handle handler;
	struct keyset keys;
	uint8_t *server_key_buf;
	uint64_t server_key_bufsize;
	int res;
	int ret;

	/* load private key */
	ret = read_pri_key(argv[1], &private_key);
	if(ret != 0) {
		goto ekey;
	}

	if(rsa_pub_key(&private_key, &server_key) != 0) {
		goto epub;
	}

	/* initiate handshake */

	pthread_t handler_thread;

	init_handler(&handler, client.fd);
	pthread_create(&handler_thread, NULL, handle_connection, &handler);

	ret = server_handshake(&handler, &private_key, &keys);
	if(ret == -1) {
		fprintf(stderr, "handshake programmatic error\n");
		goto ehandshake;
	} else if(ret > 0) {
		switch(ret) {
		case INVALID_DH_KEY:
			fprintf(stderr,
				"client provided invalid DH key\n");
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
	printf("server public key:\n");
	printbuf(server_key_buf, server_key_bufsize);
	printf("symmetric keys:\n");
	printbuf(keys.recv_symm_key, 32);
	printbuf(keys.send_symm_key, 32);
	printbuf(keys.recv_hmac_key, 32);
	printbuf(keys.send_hmac_key, 32);

	sleep(1);

	/* done */
	if(rsa_free_pubkey(&server_key) != 0) {
		fprintf(stderr,
			"failed to free public key\n");
		goto efree;
	}
	if(rsa_free_prikey(&private_key) != 0) {
		fprintf(stderr,
			"failed to free private key\n");
		goto efree;
	}
	memset(&keys, 0, sizeof(struct keyset));
	free(server_key_buf);

	end_handler(&handler);

	return 0;

eprint:
	rsa_free_pubkey(&server_key);
efree:
	free(server_key_buf);
ehandshake:
	rsa_free_prikey(&private_key);
ekey:
epub:
	end_handler(&handler);

	return 1;
}
