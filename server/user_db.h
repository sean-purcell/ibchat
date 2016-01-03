#ifndef IBCHAT_SERVER_USER_DB_H
#define IBCHAT_SERVER_USER_DB_H

#include <stdint.h>

#include <ibcrypt/rsa.h>

struct user {
	RSA_PUBLIC_KEY pkey;
	uint8_t uid[0x20];
	uint8_t und_auth[0x20];
};

int user_db_init(char *root_dir);
void user_db_destroy();

struct user *user_db_get(uint8_t *uid);
/* registers a new user */
int user_db_add(struct user u);

int user_init(uint8_t *uid, RSA_PUBLIC_KEY pkey, struct user *u);

#endif

