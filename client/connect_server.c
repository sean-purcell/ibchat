#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <ibcrypt/rsa.h>

#include "../crypto/handshake.h"
#include "../crypto/crypto_layer.h"
#include "../inet/connect.h"
#include "../util/defaults.h"

/* Returns -1 for programatic error, 1 for server error */
int connect_server(char *addr, struct con_handle *con_hndl, RSA_PUBLIC_KEY *server_key, struct keyset *keys) {
	struct sock server;

	server = client_connect(addr, DFLT_PORT);
	if(server.fd == -1) {
		if(errno == 0) {
			fprintf(stderr, "could not find server at given address\n");
		} else {
			perror("could not connect to server");
		}

		return 1;
	}

	/* initiate handshake */
	int res;
	int ret;

	pthread_t handler_thread;

	init_handler(con_hndl, server.fd);
	pthread_create(&handler_thread, NULL, handle_connection, con_hndl);

	ret = client_handshake(con_hndl, server_key, keys, &res);
	if(ret == -1) {
		fprintf(stderr, "a program error occurred during handshake\n");

		goto err;
	} else if(ret == 1) {
		fprintf(stderr, "server failed to perform handshake\n");

		goto err;
	}

	if(res != 0) {
		fprintf(stderr, "server performed invalid handshake\n");

		ret = 2;

		goto err;
	}

	/* connected */
	return 0;

err:
	end_handler(con_hndl);
	return ret;
}

