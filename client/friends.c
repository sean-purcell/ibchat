#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include <sys/stat.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/rand.h>
#include <ibcrypt/zfree.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "ibchat_client.h"
#include "friends.h"
#include "datafile.h"

static int ff_p_fill(void *_arg, uint8_t *ptr) {
	return 0;
}

static int ff_s_key(void *_arg, uint8_t *ptr, uint8_t *key) {
	struct account *arg = (struct account *) _arg;
	memcpy(key, arg->f_symm, 0x20);
	return 0;
}

static int ff_h_key(void *_arg, uint8_t *ptr, uint8_t *key) {
	struct account *arg = (struct account *) _arg;
	memcpy(key, arg->f_hmac, 0x20);
	return 0;
}

static uint64_t ff_datalen(void *_data) {
	return friend_bin_size((struct friend *) _data);
}

static uint8_t *ff_datawrite(void *_data, uint8_t *ptr) {
	return friend_write_bin((struct friend *) _data, ptr);
}

static uint8_t *ff_dataread(void **_data, uint8_t *ptr) {
	return friend_parse_bin((struct friend **) _data, ptr);
}

static struct format_desc ff_format = {
	0x00,
	ff_p_fill,
	ff_s_key,
	ff_h_key,

	offsetof(struct friend, next),
	ff_datalen,
	ff_datawrite,
	ff_dataread,
};


char *friendfile_path(struct account *acc) {
	return file_path(acc->f_file);
}

int init_friendfile(struct account *acc) {
	uint8_t buf[96];

	if(cs_rand(buf, 96) != 0) {
		fprintf(stderr, "failed to generate random numbers\n");
		return -1;
	}

	acc->friends = NULL;

	memcpy(acc->f_file, &buf[ 0], 32);
	memcpy(acc->f_symm, &buf[32], 32);
	memcpy(acc->f_hmac, &buf[64], 32);

	memsets(buf, 0, sizeof(buf));

	char *fname = friendfile_path(acc);
	if(fname == NULL) {
		return -1;
	}

	struct stat st;
	int ret = stat(fname, &st);
	if(ret != 0) {
		if(errno != ENOENT) {
			fprintf(stderr, "could not access friend file dir: "
				"%s\n", fname);
			return -1;
		}
	} else {
		fprintf(stderr, "friend file already exists, RNG unsafe: %s\n",
			fname);
		return -1;
	}

	free(fname);

	return write_friendfile(acc);
}

int write_friendfile(struct account *acc) {
	int ret;
	char *path = friendfile_path(acc);
	if(path == NULL) {
		return -1;
	}

	ret = write_datafile(path, acc, acc->friends, &ff_format);
	free(path);
	return ret;
}

int read_friendfile(struct account *acc) {
	int ret;
	char *path = friendfile_path(acc);
	if(path == NULL) {
		return -1;
	}

	ret = read_datafile(path, acc, (void **)&acc->friends, &ff_format);
	free(path);
	return ret;
}

uint64_t friend_bin_size(struct friend *f) {
	uint64_t len = 0;

	len += 8;
	len += 8;
	len += f->u_len;
	len += f->k_len;

	len += 32;

	len += 32;
	len += 32;
	len += 32;
	len += 32;
	len += 32;
	len += 32;

	len += 8;
	len += 8;

	return len;
}

uint8_t *friend_write_bin(struct friend *f, uint8_t *ptr) {
	encbe64(f->u_len, ptr); ptr += 8;
	encbe64(f->k_len, ptr); ptr += 8;

	memcpy(ptr, f->uname, f->u_len); ptr += f->u_len;
	memcpy(ptr, f->public_key, f->k_len); ptr += f->k_len;

	memcpy(ptr, f->c_file, 32); ptr += 32;

	memcpy(ptr, f->f_symm_key, 32); ptr += 32;
	memcpy(ptr, f->f_hmac_key, 32); ptr += 32;
	memcpy(ptr, f->s_symm_key, 32); ptr += 32;
	memcpy(ptr, f->s_hmac_key, 32); ptr += 32;
	memcpy(ptr, f->r_symm_key, 32); ptr += 32;
	memcpy(ptr, f->r_hmac_key, 32); ptr += 32;

	encbe64(f->s_nonce, ptr); ptr += 8;
	encbe64(f->r_nonce, ptr); ptr += 8;

	return ptr;
}

uint8_t *friend_parse_bin(struct friend **_f, uint8_t *ptr) {
	struct friend *f = malloc(sizeof(struct friend));
	if(f == NULL) {
		return NULL;
	}
	f->u_len = decbe64(ptr); ptr += 8;
	f->k_len = decbe64(ptr); ptr += 8;

	f->uname = malloc(f->u_len) + 1;
	f->public_key = malloc(f->k_len);
	if(f->uname == NULL || f->public_key == NULL) {
		return NULL;
	}

	memcpy(f->uname, ptr, f->u_len); ptr += f->u_len;
	f->uname[f->u_len] = '\0';

	memcpy(f->public_key, ptr, f->k_len); ptr += f->k_len;

	memcpy(f->c_file, ptr, 32); ptr += 32;

	memcpy(f->f_symm_key, ptr, 32); ptr += 32;
	memcpy(f->f_hmac_key, ptr, 32); ptr += 32;
	memcpy(f->s_symm_key, ptr, 32); ptr += 32;
	memcpy(f->s_hmac_key, ptr, 32); ptr += 32;
	memcpy(f->r_symm_key, ptr, 32); ptr += 32;
	memcpy(f->r_hmac_key, ptr, 32); ptr += 32;

	f->s_nonce = decbe64(ptr); ptr += 8;
	f->r_nonce = decbe64(ptr); ptr += 8;

	*_f = f;

	return ptr;
}

void friend_free(struct friend *f) {
	zfree(f->uname, f->u_len);
	zfree(f->public_key, f->k_len);
	memsets(f, 0, sizeof(struct friend));
}

void friend_free_list(struct friend *f) {
	while(f) {
		struct friend *next = f->next;
		friend_free(f);
		f = next;
	}
}

