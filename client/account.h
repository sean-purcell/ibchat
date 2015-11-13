#ifndef IBCHAT_CLIENT_ACCOUNT_H
#define IBCHAT_CLIENT_ACCOUNT_H

#include "profile.h"

struct account {
	uint64_t u_len;
	uint64_t a_len;
	uint64_t k_len;
	char *uname; /* username */
	char *addr; /* server address */
	uint8_t *key_bin; /* private key binary */
	uint8_t sfing[32]; /* server key hash */

	uint8_t f_file[32];
	uint8_t f_symm[32];
	uint8_t f_hmac[32];
	uint64_t f_nonce;

	struct friend *friends;

	struct account *next;
};

int pick_account(struct profile *prof, struct account *acc);

int init_account_file(struct account *acc);

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

