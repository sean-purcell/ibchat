#ifndef IBCHAT_CLIENT_LOGIN_H
#define IBCHAT_CLIENT_LOGIN_H

#include <ibcrypt/rsa.h>

struct login_data {
	char *uname;
	char *pass;
	RSA_KEY id;
	uint8_t symm_seed[32];
	uint8_t hmac_seed[32];
};

/* generates a random keyset */
int gen_login_data(struct login_data *data);

#endif

