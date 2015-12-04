#include <stdio.h>
#include <errno.h>

#include <sys/stat.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/rand.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/endian.h>

#include "cli.h"
#include "ibchat_client.h"
#include "notifications.h"

int notiflist_len(struct notif *n) {
	acquire_readlock(&lock);
	int num = 0;
	struct notif *cur = n;
	while(cur) {
		num++;
		cur = cur->next;
	}

	release_readlock(&lock);

	return num;
}

int init_notiffile(struct account *acc) {
	uint8_t buf[96];

	if(cs_rand(buf, 96) != 0) {
		fprintf(stderr, "failed to generate random numbers\n");
		return -1;
	}

	memcpy(acc->n_file, &buf[ 0], 32);
	memcpy(acc->n_symm, &buf[32], 32);
	memcpy(acc->n_hmac, &buf[64], 32);

	memsets(buf, 0, sizeof(buf));

	char *fname = file_path(acc->n_file);
	if(fname == NULL) {
		return -1;
	}

	struct stat st;
	int ret = stat(fname, &st);
	if(ret != 0) {
		if(errno != ENOENT) {
			fprintf(stderr, "could not access notif file dir: "
				"%s\n", fname);
			return -1;
		}
	} else {
		fprintf(stderr, "notif file already exists, RNG unsafe: %s\n",
			fname);
		return -1;
	}

	free(fname);

	return write_notiffile(acc, NULL);
}

int write_notiffile(struct account *acc, struct notif *notifs) {
	int ret = -1;

	char *path = file_path(acc->n_file);
	if(path == NULL) {
		return -1;
	}

	FILE *ff = fopen(path, "wb");
	if(ff == NULL) {
		fprintf(stderr, "failed to open notiffile for writing: %s\n",
			path);
		free(path);
		return -1;
	}
	uint64_t payload_len = 0;
	uint64_t notif_num = 0;
	uint8_t *payload = NULL;

	struct notif *cur = notifs;
	while(cur) {
		payload_len += notif_bin_len(cur);
		notif_num++;
		cur = cur->next;
	}

	uint8_t prefix[0x50];

	encbe64(  notif_num, &prefix[0]);
	encbe64(payload_len, &prefix[8]);
	if(cs_rand(&prefix[16], 32) != 0) {
		fprintf(stderr, "failed to generate random numbers\n");
		goto err;
	}
	hmac_sha256(acc->n_hmac, 32, prefix, 0x30, &prefix[0x30]);

	if(fwrite(prefix, 1, sizeof(prefix), ff) != sizeof(prefix)) {
		fprintf(stderr, "failed to write to notiffile: %s\n", path);
		goto err;
	}

	if((payload = malloc(payload_len)) == NULL) {
		goto err;
	}

	cur = notifs;
	uint8_t *ptr = payload;
	while(cur) {
		ptr = notif_bin_write(cur, ptr);
		cur = cur->next;
	}
	if(ptr - payload != payload_len) {
		fprintf(stderr, "payload length does not match written\n");
		goto err;
	}

	uint8_t key[0x20];
	SHA256_CTX kctx;
	sha256_init(&kctx);
	sha256_update(&kctx, acc->n_symm, 0x20);
	sha256_update(&kctx, &prefix[0x10], 0x20);
	sha256_final(&kctx, key);

	chacha_enc(key, 0x20, 0, payload, payload, payload_len);

	memsets(key, 0, sizeof(key));

	if(fwrite(payload, 1, payload_len, ff) != payload_len) {
		fprintf(stderr, "failed to write to notiffile: %s\n", path);
		goto err;
	}

	uint8_t mac[0x20];
	HMAC_SHA256_CTX hctx;
	hmac_sha256_init(&hctx, acc->n_hmac, 32);
	hmac_sha256_update(&hctx, prefix, sizeof(prefix));
	hmac_sha256_update(&hctx, payload, payload_len);
	hmac_sha256_final(&hctx, mac);
	if(fwrite(mac, 1, 0x20, ff) != 0x20) {
		fprintf(stderr, "failed to write to notiffile: %s\n", path);
		goto err;
	}

	ret = 0;
err:
	fclose(ff);
	if(payload) zfree(payload, payload_len);
	free(path);

	return ret;
}

uint64_t notif_bin_len(struct notif *n) {
	uint64_t len = 1;
	switch(n->type) {
	case 1:
		len += 0x20;
		len += 0x08;
		break;
	case 2:
		len += 0x08;
		len += 0x08;
		len += n->fr->u_len;
		len += n->fr->k_len;
		break;
	case 3:
		len += 0x20;
		break;
	}

	return len;
}

uint8_t *notif_bin_write(struct notif *n, uint8_t *ptr) {
	*ptr = (uint8_t) n->type;
	ptr++;
	switch(n->type) {
	case 1:
		memcpy(ptr, n->fr->c_file, 0x20); ptr += 0x20;
		encbe64(n->nunread, ptr); ptr += 8;
		break;
	case 2:
		encbe64(n->freq->u_len, ptr); ptr += 8;
		encbe64(n->freq->k_len, ptr); ptr += 8;
		memcpy(ptr, n->freq->uname, n->freq->u_len);
			ptr += n->freq->u_len;
		memcpy(ptr, n->freq->pkey, n->freq->k_len);
			ptr += n->freq->k_len;
		break;
	case 3:
		memcpy(ptr, n->fr->c_file, 0x20); ptr += 0x20;
		break;
	}

	return ptr;
}

uint8_t *notif_bin_parse(struct account *acc, struct notif *n, uint8_t *ptr) {
	n->type = *ptr;
	ptr++;

	struct friend *f;

	switch(n->type) {
	case 1:
		n->nunread = decbe64(&ptr[0x20]);
	case 3:
		f = acc->friends;
		while(f) {
			if(memcmp(f->c_file, ptr, 0x20) == 0) {
				n->fr = f;
				break;
			}
			f = f->next;
		}
		if(!f) {
			fprintf(stderr, "referenced friend not found\n");
			return NULL;
		}
		ptr += 0x28;
		break;
	case 2:
		if((n->freq = malloc(sizeof(struct friendreq))) == NULL) {
			goto memfail;
		}
		n->freq->u_len = decbe64(ptr); ptr += 8;
		n->freq->k_len = decbe64(ptr); ptr += 8;
		if((n->freq->uname = malloc(n->freq->u_len+1)) == NULL) {
			goto memfail;
		}
		if((n->freq->pkey = malloc(n->freq->k_len)) == NULL) {
			goto memfail;
		}

		memcpy(n->freq->uname, ptr, n->freq->u_len);
		n->freq->uname[n->freq->u_len] = '\0';
		ptr += n->freq->u_len;

		memcpy(n->freq->pkey, ptr, n->freq->k_len);
		ptr += n->freq->k_len;
		break;
	}

	return ptr;

memfail:
	fprintf(stderr, "failed to allocate memory\n");
	return NULL;
}

