#ifndef IBCHAT_CLIENT_LOGIN_H
#define IBCHAT_CLIENT_LOGIN_H

struct login_data {
	char *uname;
	char *pass;
	RSA_KEY id;
	uint8_t symm_seed[32];
	uint8_t hmac_seed[32];
};

#endif

