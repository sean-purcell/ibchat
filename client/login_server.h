#ifndef IBCHAT_CLIENT_LOGIN_SERVER_H
#define IBCHAT_CLIENT_LOGIN_SERVER_H

#include <ibcrypt/rsa.h>

#include "../inet/protocol.h"
#include "../crypto/crypto_layer.h"

#include "account.h"

struct server_connection {
	struct con_handle ch;
	RSA_PUBLIC_KEY server_key;
	struct keyset keys;

	struct account *acc;
};

int create_account(struct account *acc, struct server_connection *sc);

void cleanup_server_connection(struct server_connection *sc);

#endif

