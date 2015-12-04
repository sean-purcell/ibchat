#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <stddef.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/rand.h>
#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/scrypt.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/endian.h>
#include <libibur/util.h>

#include "userfile.h"
#include "account.h"
#include "profile.h"
#include "uname.h"
#include "ibchat_client.h"
#include "datafile.h"

static const char *UFILE_SUFFIX = "ufile.ibc";
static char *UFILE_PATH = NULL;

static int init_acc_file_str() {
	if(UFILE_PATH != NULL) {
		return 0;
	}
	UFILE_PATH = malloc(strlen(ROOT_DIR) + strlen(UFILE_SUFFIX) + 1);
	if(UFILE_PATH == NULL) {
		return -1;
	}

	strcpy(UFILE_PATH, ROOT_DIR);
	strcpy(&UFILE_PATH[strlen(ROOT_DIR)], UFILE_SUFFIX);
	UFILE_PATH[strlen(ROOT_DIR) + strlen(UFILE_SUFFIX)] = '\0';

	return 0;
}

int user_exist() {
	if(init_acc_file_str() != 0) {
		return -1;
	}

	/* check if theres a file at the expected address */
	FILE* afile = fopen(UFILE_PATH, "rb");
	if(afile == NULL) {
		if(errno == ENOENT) {
			return 0;
		} else {
			return -1;
		}
	}
	fclose(afile);

	return 1;
}

static int uf_p_fill(void *_arg, uint8_t *ptr) {
	struct profile *arg = (struct profile *) _arg;

	memcpy(&ptr[0x00], arg->salt, 0x20);
	memcpy(&ptr[0x20], arg->pw_check, 0x20);

	return 0;
}

static int uf_s_key(void *_arg, uint8_t *ptr, uint8_t *key) {
	struct profile *arg = (struct profile *) _arg;

	if(!arg->expanded) {
		memcpy(arg->salt, ptr, 0x20);
		memcpy(arg->pw_check, &ptr[0x20], 0x20);
		if(key_expand(arg) != 0) {
			return -1;
		}
	}

	memcpy(key, arg->symm_key, 0x20);
	return 0;
}

static int uf_h_key(void *_arg, uint8_t *ptr, uint8_t *key) {
	struct profile *arg = (struct profile *) _arg;

	if(!arg->expanded) {
		memcpy(arg->salt, ptr, 0x20);
		memcpy(arg->pw_check, &ptr[0x20], 0x20);
		if(key_expand(arg) != 0) {
			return -1;
		}
	}

	memcpy(key, arg->hmac_key, 0x20);
	return 0;
}

static uint64_t uf_datalen(void *_data) {
	return account_bin_size((struct account *) _data);
}

static uint8_t *uf_datawrite(void *_data, uint8_t *ptr) {
	return account_write_bin((struct account *) _data, ptr);
}

static uint8_t *uf_dataread(void **_data, void *arg, uint8_t *ptr) {
	return account_parse_bin((struct account **) _data, ptr);
}

static struct format_desc uf_format = {
	0x40,
	uf_p_fill,
	uf_s_key,
	uf_h_key,

	offsetof(struct account, next),
	uf_datalen,
	uf_datawrite,
	uf_dataread,
};

int write_userfile(struct profile *user) {
	if(init_acc_file_str() != 0) {
		return -1;
	}
	return write_datafile(UFILE_PATH, user, user->server_accounts, &uf_format);
}

int read_userfile(struct profile *user) {
	if(init_acc_file_str() != 0) {
		return -1;
	}
	user->expanded = 0;
	return read_datafile(UFILE_PATH, user, (void**)&user->server_accounts, &uf_format);
}

