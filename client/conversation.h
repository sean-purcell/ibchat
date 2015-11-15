#ifndef CLIENT_CONVERSATION_H
#define CLIENT_CONVERSATION_H

#include "account.h"
#include "login_server.h"

struct cmessage {
	/* 0: you, 1: them */
	int sender;
	char *text;

	struct cmessage *next, *prev;
};

int select_conversation(struct account *acc);
int start_conversation(struct friend *f);

int cfile_init(struct friend *f);
struct cmessage *cfile_load(struct friend *f);

#endif

