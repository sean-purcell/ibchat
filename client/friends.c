#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/stat.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/rand.h>
#include <ibcrypt/zfree.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "ibchat_client.h"
#include "friends.h"

char *friendfile_path(struct account *acc) {
	size_t rootdir_len = strlen(ROOT_DIR);
	char *fname = malloc(rootdir_len + 64 + 1);
	if(fname == NULL) {
		fprintf(stderr, "failed to allocate memory for path\n");
		return NULL;
	}

	memcpy(fname, ROOT_DIR, rootdir_len);
	to_hex(acc->f_file, 32, &fname[rootdir_len]);
	fname[rootdir_len + 64] = '\0';

	return fname;
}

int init_friendfile(struct account *acc) {
	uint8_t buf[96];

	if(cs_rand(buf, 96) != 0) {
		fprintf(stderr, "failed to generate random numbers\n");
		return -1;
	}

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

	acc->f_nonce = 0;

	return write_friendfile(acc);
}


int write_friendfile(struct account *acc) {
	char *path = friendfile_path(acc);
	if(path == NULL) {
		return -1;
	}

	FILE *ff = fopen(path, "wb");
	uint8_t *payload = NULL;
	if(ff == NULL) {
		fprintf(stderr, "failed to open friendfile for writing: %s\n",
			path);
		free(path);
		return -1;
	}
	free(path);

	uint64_t len = 8 + 32;
	uint64_t fnum = 0;
	struct friend *cur = acc->friends;
	while(cur) {
		len += friend_bin_size(cur);
		cur = cur->next;
		fnum++;
	}
	len += 32;

	payload = malloc(len);
	if(payload == NULL) {
		fprintf(stderr, "failed to allocate memory for payload\n");
	}

	CHACHA_CTX cctx;
	chacha_init(&cctx, acc->f_symm, 32, acc->f_nonce);

	encbe64(fnum, payload);
	chacha_stream(&cctx, payload, payload, 8);
	hmac_sha256(acc->f_hmac, 32, payload, 8, &payload[8]);

	cur = acc->friends;
	uint8_t *ptr = payload + 8 + 32;
	while(cur) {
		ptr = friend_write_bin(cur, ptr);
	}
	if(ptr - payload != len - 32) {
		fprintf(stderr, "expected write len did not match actual\n");
	}

	chacha_stream(&cctx, payload + 40, payload + 40, ptr - payload - 40);
	chacha_final(&cctx);

	hmac_sha256(acc->f_hmac, 32, payload, len - 32, &payload[len - 32]);

	if(fwrite(payload, 1, len, ff) != len) {
		fprintf(stderr, "error writing payload to file: %s\n",
			strerror(errno));
		goto err;
	}

	fclose(ff);
	zfree(payload, len);
	return 0;
err:
	fclose(ff);
	if(payload) zfree(payload, len);
	return -1;
}

struct friend *read_friendfile(struct account *acc);

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

	len += 8;
	len += 8;
	len += 8;

	return len;
}

uint8_t *friend_write_bin(struct friend *f, uint8_t *ptr) {
	encbe64(f->u_len, ptr); ptr += 8;
	encbe64(f->k_len, ptr); ptr += 8;

	memcpy(ptr, f->uname, f->u_len); ptr += f->u_len;
	memcpy(ptr, f->public_key, f->k_len); ptr += f->k_len;

	memcpy(ptr, f->f_symm_key, 32); ptr += 32;
	memcpy(ptr, f->f_hmac_key, 32); ptr += 32;
	memcpy(ptr, f->s_symm_key, 32); ptr += 32;
	memcpy(ptr, f->s_hmac_key, 32); ptr += 32;
	memcpy(ptr, f->r_symm_key, 32); ptr += 32;
	memcpy(ptr, f->r_hmac_key, 32); ptr += 32;

	encbe64(f->f_nonce, ptr); ptr += 8;
	encbe64(f->s_nonce, ptr); ptr += 8;
	encbe64(f->r_nonce, ptr); ptr += 8;

	return ptr;
}

uint8_t *friend_parse_bin(struct friend *f, uint8_t *ptr) {
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

	memcpy(f->f_symm_key, ptr, 32); ptr += 32;
	memcpy(f->f_hmac_key, ptr, 32); ptr += 32;
	memcpy(f->s_symm_key, ptr, 32); ptr += 32;
	memcpy(f->s_hmac_key, ptr, 32); ptr += 32;
	memcpy(f->r_symm_key, ptr, 32); ptr += 32;
	memcpy(f->r_hmac_key, ptr, 32); ptr += 32;

	f->f_nonce = decbe64(ptr); ptr += 8;
	f->s_nonce = decbe64(ptr); ptr += 8;
	f->r_nonce = decbe64(ptr); ptr += 8;

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

