#ifndef IBCHAT_SERVER_USER_DB_H
#define IBCHAT_SERVER_USER_DB_H

#include <stdint.h>

#include <ibcrypt/rsa.h>

struct user {
	RSA_PUBLIC_KEY pkey;
	uint8_t uid[0x20];
	uint8_t undel[0x20];
};

int init_user_db(char *root_dir);

#endif

