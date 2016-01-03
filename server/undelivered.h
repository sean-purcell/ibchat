#ifndef SERVER_UNDELIVERED_H
#define SERVER_UNDELIVERED_H

#include <stdint.h>

#include "user_db.h"

struct umessage {
	uint8_t *message;
	uint64_t len;
	struct umessage *next;
};

int undel_init_file(struct user *u);
int undel_add_message(struct user *u, uint8_t *message, uint64_t len);
int undel_load(struct user *u, struct umessage **messages);

struct umessage *alloc_umessage(uint64_t len);
void free_umessage(struct umessage *m);
void free_umessage_list(struct umessage *m);

int undel_init(char *root_dir);

#endif

