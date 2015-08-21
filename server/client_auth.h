#ifndef IBCHAT_SERVER_CLIENT_AUTH_H
#define IBCHAT_SERVER_CLIENT_AUTH_H

#include "../crypto/crypto_layer.h"
#include "../inet/protocol.h"

#include "client_handler.h"

int auth_user(struct client_handler *cli_hndl, struct con_handle *con_hndl, struct keyset *keys, uint8_t *uid);

#endif

