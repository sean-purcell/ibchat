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
#include "../util/log.h"

/* Returns -1 for programatic error, 1 for server error */
int connect_server(char *addr, struct con_handle **con_hndl, RSA_PUBLIC_KEY *server_key, struct keyset *keys) {
	struct sock server;

	server = client_connect(addr, DFLT_PORT);
	if(server.fd == -1) {
		if(errno == 0) {
			ERR("could not find server at given address");
		} else {
			ERR("could not connect to server: %s", strerror(errno));
		}

		return 1;
	}

	/* initiate handshake */
	int res;
	int ret;

	pthread_t handler_thread;

	launch_handler(&handler_thread, con_hndl, server.fd);

	ret = client_handshake(*con_hndl, server_key, keys, &res);
	if(ret == -1) {
		ERR("a program error occurred during handshake");

		goto err;
	} else if(ret == 1) {
		ERR("server failed to perform handshake");

		goto err;
	}

	if(res != 0) {
		ERR("server performed invalid handshake");

		ret = 2;

		goto err;
	}

	/* connected */
	return 0;

err:
	end_handler(*con_hndl);
	return ret;
}

