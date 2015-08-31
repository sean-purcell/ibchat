#include <string.h>

#include <ibcrypt/sha256.h>

#include <libibur/util.h>

#include "account_file.h"

/* contains details such as root directory */
#include "ibchat_client.h"

int user_exist(const char* uname) {
	char *expected_dir = malloc(strlen(ROOT_DIR) + 64 + 1);
	if(expected_dir == NULL){
		return -1;
	}

	uint8_t hash[0x20];

	/* include the \0 in the hash */
	sha256((uint8_t *) uname, strlen(uname) + 1, hash);

	to_hex(hash, 0x20, &expected_dir[strlen(ROOT_DIR)]);
	expected_dir[strlen(ROOT_DIR) + 64] = '\0';

	/* check if there exists a user file for this user */
}

