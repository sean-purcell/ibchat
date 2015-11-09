#ifndef SERVER_UNDELIVERED_H
#define SERVER_UNDELIVERED_H

#include <stdint.h>

#include "user_db.h"

int add_undelivered_message(struct user *u, uint8_t *message, uint64_t len);

#endif

