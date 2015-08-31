#ifndef IBCHAT_CLIENT_CONNECT_SERVER_H
#define IBCHAT_CLIENT_CONNECT_SERVER_H

#include "../crypto/crypto_layer.h"
#include "../inet/connect.h"

int connect_server(char *addr, struct con_handle *con_hndl, RSA_PUBLIC_KEY *server_key, struct keyset *keys);

#endif

