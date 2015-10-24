#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>

#include <ibcrypt/zfree.h>

#include <libibur/endian.h>

#include "account.h"
#include "profile.h"
#include "login_server.h"

#include "../util/line_prompt.h"

int pick_account(struct profile *prof, struct account *acc) {
	if(prof->server_accounts == NULL) {
		printf("no accounts found\nregister a new one? [y/n] ");

		char *ans = line_prompt(NULL, NULL, 0);
		if(ans == NULL) {
			perror("failed to read response");
			return -1;
		}

		if((ans[0] | 32) != 'y') {
			return 1;
		}

		return 0x55;
	}

	uint64_t idx = 1;
	struct account *acc_list = prof->server_accounts;

	printf("select an account:\n");
	printf("%4d: create a new account\n", 0);

	while(acc_list) {
		printf("%4" PRIu64 ": %s, %s\n", idx, acc_list->uname, acc_list->addr);
		idx++;
		acc_list = acc_list->next;
	}

	uint64_t selection = num_prompt("selection", 0, idx);

	if(selection == ULLONG_MAX) {
		perror("failed to read response");
		return -1;
	}

	if(selection == 0) {
		return 0x55;
	} else {
		idx = 1;
		acc_list = prof->server_accounts;
		while(acc_list) {
			if(idx == selection) {
				*acc = *acc_list;
				acc->next = NULL;

				goto found;
			}

			idx++;
			acc_list = acc_list->next;
		}

		fprintf(stderr, "failed to find account corresponding to selection: %" PRIu64 "\n", selection);
		return -1;

		found:;
	}

	return 0;
}

/* returns the binary space required for this account */
uint64_t account_bin_size(struct account *acc) {
	uint64_t size = 0;
	size += 8;
	size += 8;
	size += 8;
	size += acc->u_len;
	size += acc->a_len;
	size += acc->k_len;
	size += 0x20;

	return size;
}

/* returns the pointer at the end of the section written to
 * NULL if it failed */
uint8_t *account_write_bin(struct account *acc, uint8_t *ptr) {
	encbe64(acc->u_len, ptr); ptr += 8;
	encbe64(acc->a_len, ptr); ptr += 8;
	encbe64(acc->k_len, ptr); ptr += 8;
	memcpy(ptr, acc->uname, acc->u_len); ptr += acc->u_len;
	memcpy(ptr, acc->addr, acc->a_len); ptr += acc->a_len;
	memcpy(ptr, acc->key_bin, acc->k_len); ptr += acc->k_len;
	memcpy(ptr, acc->sfing, 0x20); ptr += 0x20;

	return ptr;
}

/* returns the pointer at the end of the section written to
 * NULL if it failed */
uint8_t *account_parse_bin(struct account **acc, uint8_t *ptr) {
	struct account *ap = malloc(sizeof(struct account));
	if(ap == NULL) {
		return NULL;
	}

	ap->u_len = decbe64(ptr); ptr += 8;
	ap->a_len = decbe64(ptr); ptr += 8;
	ap->k_len = decbe64(ptr); ptr += 8;

	ap->uname = malloc(ap->u_len + 1);
	if(ap->uname == NULL) {
		return NULL;
	}
	ap->addr = malloc(ap->a_len + 1);
	if(ap->addr == NULL) {
		return NULL;
	}
	ap->key_bin = malloc(ap->k_len);
	if(ap->key_bin == NULL) {
		return NULL;
	}

	memcpy(ap->uname, ptr, ap->u_len);
	ptr += ap->u_len;
	ap->uname[ap->u_len] = '\0';

	memcpy(ap->addr, ptr, ap->a_len);
	ptr += ap->a_len;
	ap->addr[ap->a_len] = '\0';

	memcpy(ap->key_bin, ptr, ap->k_len);
	ptr += ap->k_len;

	memcpy(ap->sfing, ptr, 0x20); ptr += 0x20;

	*acc = ap;
	return ptr;
}

void account_free(struct account *acc) {
	zfree(acc->uname, acc->u_len);
	zfree(acc->addr, acc->a_len);
	zfree(acc->key_bin, acc->k_len);

	zfree(acc, sizeof(struct account));
}

void account_free_list(struct account *acc) {
	while(acc != NULL) {
		struct account *next = acc->next;
		account_free(acc);
		acc = next;
	}
}

