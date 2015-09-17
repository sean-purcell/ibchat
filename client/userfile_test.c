#include <stdio.h>
#include <stdlib.h>

#include <ibcrypt/rsa_util.h>

#include "userfile.h"
#include "login.h"

#include "../util/getpass.h"
#include "../util/user.h"

int main() {
	struct profile data;
	struct profile data_f;

	char *username;
	char *password;

	uint8_t *key1;
	uint8_t *key2;

	int ret;

	if(gen_profile(&data) != 0) {
		fprintf(stderr, "failed to generate login data\n");
		return 1;
	}

	username = getusername(NULL, stdout);
	password = ibchat_getpass("password", NULL, 0);
	if(username == NULL || password == NULL) {
		fprintf(stderr, "failed to read username or password\n");
		return 1;
	}

	printf("inputted username: %s\n", username);
	printf("inputted password: %s\n", password);

	data.uname = username;
	data.pass = password;
	data_f = data;

	if((ret = write_userfile(&data, "tmp.usr")) != 0) {
		fprintf(stderr, "failed to write userfile: %d\n", ret);
		return 1;
	}
	if((ret = read_userfile(&data_f, "tmp.usr")) != 0) {
		fprintf(stderr, "failed to read userfile: %d\n", ret);
		return 1;
	}

	if(memcmp(data.symm_seed, data_f.symm_seed, 32) != 0) {
		fprintf(stderr, "symm seeds don't match\n");
		return 1;
	}
	if(memcmp(data.hmac_seed, data_f.hmac_seed, 32) != 0) {
		fprintf(stderr, "hmac seeds don't match\n");
		return 1;
	}

	key1 = malloc(rsa_prikey_bufsize(data.id.bits));
	key2 = malloc(rsa_prikey_bufsize(data_f.id.bits));

	rsa_prikey2wire(&data.id, key1, rsa_prikey_bufsize(data.id.bits));
	rsa_prikey2wire(&data_f.id, key2, rsa_prikey_bufsize(data_f.id.bits));

	if(memcmp(key1, key2, rsa_prikey_bufsize(data.id.bits)) != 0) {
		fprintf(stderr, "id keys don't match\n");
		return 1;
	}

	free(key1);
	free(key2);
	free(username);
	free(password);
	rsa_free_prikey(&data.id);
	rsa_free_prikey(&data_f.id);
}

