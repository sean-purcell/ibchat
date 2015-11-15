#ifndef CLIENT_FRIENDREQ_H
#define CLIENT_FRIENDREQ_H

#include "login_server.h"

struct friendreq {
	char *uname;
	uint8_t pkey;
};

int send_friendreq(char *target, struct server_connection *sc);


#endif

