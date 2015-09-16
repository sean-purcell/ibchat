#ifndef IBCHAT_CLIENT_LOGIN_H
#define IBCHAT_CLIENT_LOGIN_H

#include <ibcrypt/rsa.h>

#include "login.h"

struct account {
	uint64_t u_len;
	uint64_t a_len;
	uint64_t k_len;
	char *uname;
	char *addr;
	uint8_t *key_bin;

	struct account *next;
};

struct login_data {
	char *pass;
	RSA_KEY id;
	uint8_t salt[32];
	uint8_t pw_check[32];
	uint8_t symm_key[32];
	uint8_t hmac_key[32];
	uint64_t nonce;

	struct account *server_accounts;
};

int login_account(char *uname, char *pass, struct account *acc);

/* generates a random keyset */
int gen_login_data(struct login_data *data);

/* prompts an input line from the console */
char* line_prompt(const char* prompt, const char* confprompt, int hide);

/* returns the binary space required for this account */
uint64_t account_bin_size(struct account *acc);
/* returns the pointer at the end of the section written to
 * NULL if it failed */
uint8_t *account_write_bin(struct account *acc, uint8_t *ptr);
/* returns the pointer at the end of the section written to
 * NULL if it failed */
uint8_t *account_parse_bin(struct account **acc, uint8_t *ptr);

void account_free(struct account *acc);
void account_free_list(struct account *acc);

#endif

