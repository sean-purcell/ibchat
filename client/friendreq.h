#ifndef CLIENT_FRIENDREQ_H
#define CLIENT_FRIENDREQ_H

#include "../inet/message.h"

#include "login_server.h"
#include "account.h"

struct friendreq {
	uint64_t u_len;
	uint64_t k_len;

	char *uname;
	uint8_t *pkey;
};

struct message *pkey_resp;

int send_friendreq(struct server_connection *sc, struct account *acc);
void free_friendreq(struct friendreq *freq);

#endif

