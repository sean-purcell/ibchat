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

struct friend *cur_conv;
struct cmessage *new_messages;

int select_conversation(struct account *acc);
int start_conversation(struct friend *f);

int cfile_init(struct friend *f);
int cfile_add(struct friend *f, struct cmessage *m);
struct cmessage *cfile_load(struct friend *f);

struct cmessage *alloc_cmessage(uint64_t len);
void free_cmessage(struct cmessage *m);
void free_cmessage_list(struct cmessage *m);

#endif

