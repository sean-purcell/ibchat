#ifndef IBCHAT_CLIENT_LOGIN_H
#define IBCHAT_CLIENT_LOGIN_H

#include <ibcrypt/rsa.h>

#include "login.h"

struct login_data {
	char *uname;
	char *pass;
	RSA_KEY id;
	uint8_t symm_seed[32];
	uint8_t hmac_seed[32];

	struct account *server_accounts;
};

int login_account(char *uname, char *pass, struct account *acc);

/* generates a random keyset */
int gen_login_data(struct login_data *data);

/* prompts an input line from the console */
char* line_prompt(const char* prompt, const char* confprompt, int hide);

#endif

