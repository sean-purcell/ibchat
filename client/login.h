#ifndef IBCHAT_CLIENT_LOGIN_H
#define IBCHAT_CLIENT_LOGIN_H

#include <ibcrypt/rsa.h>

#include "login.h"

struct profile {
	char *pass;
	uint8_t salt[32];
	uint8_t pw_check[32];
	uint8_t symm_key[32];
	uint8_t hmac_key[32];
	uint64_t nonce;

	struct account *server_accounts;
};

int login_profile(char *pass, struct profile *acc);

int add_account(struct profile* prof, struct account *acc);

int rewrite_profile(struct profile *prof);
int profile_reseed(struct profile *prof);

/* generates a random keyset */
int gen_profile(struct profile *data);

#endif

