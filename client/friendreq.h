#ifndef CLIENT_FRIENDREQ_H
#define CLIENT_FRIENDREQ_H

#include "../inet/message.h"

#include "login_server.h"

struct friendreq {
	char *uname;
	uint8_t pkey;
};

struct message *pkey_resps;

int send_friendreq(struct server_connection *sc);

#endif

