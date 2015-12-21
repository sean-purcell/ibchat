#include <stdio.h>

#include <ibcrypt/rand.h>
#include <ibcrypt/zfree.h>
#include <ibcrypt/scrypt.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "profile.h"
#include "account.h"
#include "userfile.h"
#include "ibchat_client.h"

#include "../util/line_prompt.h"
#include "../util/log.h"

int register_profile(char *pass, struct profile *acc);

/* the pointers can be left as null to prompt for them */
int login_profile(char *pass, struct profile *prof) {
	int exist = user_exist();
	if(exist == -1) {
		perror("error finding user file");
		return -1;
	}
	if(exist == 0) {
		return register_profile(pass, prof);
	}

	int prmpt_ps = 0;

	if(pass == NULL) {
		prmpt_ps = 1;
		pass = line_prompt("password", NULL, 1);
		if(pass == NULL) {
			perror("failed to read password");
			return -1;
		}
	}

	if(prmpt_ps) {
		prof->pass = pass;
	} else {
		prof->pass = strdup(pass);
		if(prof->pass == NULL) {
			perror("failed to duplicate password");
			return -1;
		}
	}

	int ret;
	if((ret = read_userfile(prof)) != 0) {
		ERR("failed to read userfile: %d", ret);
		goto err;
	}

	return 0;
err:
	zfree(prof->pass, strlen(prof->pass));
	return -1;
}

int register_profile(char *pass, struct profile *prof) {
	printf("profile not found\ncreate new profile? [y/n] ");
	fflush(stdout);

	int ans = yn_prompt();
	if(ans != 1) {
		return 1;
	}

	int prmpt_ps = 0;

	if(pass == NULL) {
		prmpt_ps = 1;
		pass = line_prompt("password", "confirm password", 1);
		if(pass == NULL) {
			perror("failed to read password");
			return -1;
		}
	}

	if(prmpt_ps) {
		prof->pass = pass;
	} else {
		prof->pass = strdup(pass);
		if(prof->pass == NULL) {
			perror("failed to duplicate password");
			return -1;
		}
	}

	if(gen_profile(prof)) {
		ERR("failed to generate profile data");
		goto err;
	}
	int ret;
	if((ret = write_userfile(prof)) != 0) {
		ERR("failed to write userfile: %d", ret);
		goto err;
	}

	return 0;

err:
	zfree(prof->pass, strlen(prof->pass));
	return -1;
}

int add_account(struct profile* prof, struct account *acc) {
	struct account **cur = &prof->server_accounts;
	while(*cur != NULL) {
		cur = &(*cur)->next;
	}

	*cur = acc;

	if(rewrite_profile(prof) != 0) {
		return 1;
	}

	return 0;
}

int rewrite_profile(struct profile *prof) {
	prof->nonce++;
	if(prof->nonce == 0) {
		if(profile_reseed(prof) != 0) {
			return 1;
		}
	}

	if(write_userfile(prof) != 0) {
		ERR("failed to write userfile");
	}

	return 0;
}

int check_userfile(struct profile *prof) {
	if(!userfile_dirty) return 0;
	return rewrite_profile(prof);
}

int profile_reseed(struct profile *prof) {
	printf("your user profile has been written 2^64 times, reseeding password\n");
	if(cs_rand(prof->salt, 32) != 0) {
		ERR("failed to generate random numbers");
		return 1;
	}

	uint8_t scrypt_out[96];
	if(scrypt(prof->pass, strlen(prof->pass), prof->salt, 32,
		1ULL << 16, 8, 1, 96, scrypt_out) != 0) {
		ERR("scrypt failed to generate new keys");
		return 1;
	}

	memcpy(prof->pw_check, &scrypt_out[ 0], 32);
	memcpy(prof->symm_key, &scrypt_out[32], 32);
	memcpy(prof->hmac_key, &scrypt_out[64], 32);

	memsets(scrypt_out, 0, 96);

	return 0;
}

/* data->pass should be prepopulated with a null terminated password */
int gen_profile(struct profile *data) {
	if(cs_rand(data->salt, 32) != 0) {
		return -1;
	}
	data->nonce = 0;
	data->server_accounts = NULL;

	uint8_t scrypt_out[96];

	if(scrypt(data->pass, strlen(data->pass), data->salt, 32,
		(uint64_t)1 << 16, 8, 1, 96, scrypt_out) != 0) {
		return -1;
	}

	memcpy(data->pw_check, &scrypt_out[ 0], 32);
	memcpy(data->symm_key, &scrypt_out[32], 32);
	memcpy(data->hmac_key, &scrypt_out[64], 32);

	memset(scrypt_out, 0, 96);

	return 0;
}

int key_expand(struct profile *prof) {
	int ret = -1;

	uint8_t scrypt_out[0x60];
	uint8_t *pw_check = &scrypt_out[0x00];
	uint8_t *symm_key = &scrypt_out[0x20];
	uint8_t *hmac_key = &scrypt_out[0x40];

	if(scrypt(prof->pass, strlen(prof->pass), prof->salt, 32,
		(uint64_t)1 << 16, 8, 1, 96, scrypt_out) != 0) {
		ERR("failed to expand password");
		goto err;
	}

	if(memcmp_ct(pw_check, prof->pw_check, 0x20) != 0) {
		ERR("password incorrect");
		goto err;
	}

	memcpy(prof->pw_check, pw_check, 0x20);
	memcpy(prof->symm_key, symm_key, 0x20);
	memcpy(prof->hmac_key, hmac_key, 0x20);

	prof->expanded = 1;
	ret = 0;
err:
	memsets(scrypt_out, 0, sizeof(scrypt_out));
	return ret;
}

