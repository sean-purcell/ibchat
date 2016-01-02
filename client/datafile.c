#include <stdio.h>
#include <stdint.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/rand.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "datafile.h"

#include "../util/log.h"

int write_datafile(char *path, void *arg, void *data, struct format_desc *f) {
	int ret = -1;

	uint8_t *payload = NULL;
	uint64_t payload_len = 0;
	uint64_t payload_num = 0;

	uint8_t *prefix = NULL;
	uint64_t pref_len = 0;

	uint8_t symm_key[0x20];
	uint8_t hmac_key[0x20];

	uint8_t enc_key[0x20];

	FILE *ff = fopen(path, "wb");
	if(ff == NULL) {
		ERR("failed to open file for writing: %s", path);
		goto err;
	}

	pref_len = 0x50 + f->pref_len;
	prefix = malloc(pref_len);
	if(prefix == NULL) {
		ERR("failed to allocate memory");
		goto err;
	}

	void *cur = data;
	while(cur) {
		payload_len += f->datalen(cur);
		payload_num++;

		cur = *((void **) ((char*)cur + f->next_off));
	}

	encbe64(payload_num, &prefix[0]);
	encbe64(payload_len, &prefix[8]);
	if(cs_rand(&prefix[0x10], 0x20) != 0) {
		ERR("failed to generate random numbers");
		goto err;
	}
	if(f->p_fill(arg, &prefix[0x30]) != 0) {
		goto err;
	}

	if(f->s_key(arg, &prefix[0x30], symm_key) != 0) {
		goto err;
	}
	if(f->h_key(arg, &prefix[0x30], hmac_key) != 0) {
		goto err;
	}

	hmac_sha256(hmac_key, 0x20, prefix, pref_len - 0x20, &prefix[pref_len - 0x20]);

	SHA256_CTX kctx;
	sha256_init(&kctx);
	sha256_update(&kctx, symm_key, 0x20);
	sha256_update(&kctx, &prefix[0x10], 0x20);
	sha256_final(&kctx, enc_key);

	payload = malloc(payload_len);
	if(payload == NULL) {
		ERR("failed to allocate memory");
		goto err;
	}

	cur = data;
	uint8_t *ptr = payload;
	while(cur) {
		ptr = f->datawrite(cur, ptr);
		if(ptr == NULL) {
			goto err;
		}

		cur = *((void **) ((char*)cur + f->next_off));
	}
	if(ptr - payload != payload_len) {
		ERR("written length does not match expected");
		goto err;
	}

	chacha_enc(enc_key, 0x20, 0, payload, payload, payload_len);

	HMAC_SHA256_CTX hctx;
	hmac_sha256_init(&hctx, hmac_key, 0x20);
	hmac_sha256_update(&hctx, prefix, pref_len);
	hmac_sha256_update(&hctx, payload, payload_len);

	uint8_t mac[0x20];
	hmac_sha256_final(&hctx, mac);

	if(fwrite(prefix, 1, pref_len, ff) != pref_len) {
		goto writerr;
	}
	if(payload_len > 0) {
		if(fwrite(payload, 1, payload_len, ff) != payload_len) {
			goto writerr;
		}
	}
	if(fwrite(mac, 1, 0x20, ff) != 0x20) {
		goto writerr;
	}

	ret = 0;

err:
	if(ff) fclose(ff);
	if(payload) zfree(payload, payload_len);
	memsets(enc_key, 0, sizeof(enc_key));
	memsets(symm_key, 0, sizeof(symm_key));
	memsets(hmac_key, 0, sizeof(hmac_key));

	return ret;

writerr:
	ERR("failed to write to file: %s", path);
	goto err;
}

int read_datafile(char *path, void *arg, void **data, struct format_desc *f) {
	int ret = -1;

	uint8_t *payload = NULL;
	uint64_t payload_len = 0;
	uint64_t payload_num = 0;

	uint8_t *prefix = NULL;
	uint64_t pref_len = 0;

	uint8_t symm_key[0x20];
	uint8_t hmac_key[0x20];

	uint8_t enc_key[0x20];

	uint8_t mac1[0x20];
	uint8_t mac2c[0x20];
	uint8_t mac2f[0x20];

	FILE *ff = fopen(path, "rb");
	if(ff == NULL) {
		ERR("failed to open file for reading: %s", path);
		goto err;
	}

	pref_len = 0x50 + f->pref_len;
	prefix = malloc(pref_len);
	if(prefix == NULL) {
		ERR("failed to allocate memory");
		goto err;
	}

	if(fread(prefix, 1, pref_len, ff) != pref_len) {
		goto readerr;
	}

	payload_num = decbe64(&prefix[0]);
	payload_len = decbe64(&prefix[8]);

	if(f->s_key(arg, &prefix[0x30], symm_key) != 0) {
		goto err;
	}
	if(f->h_key(arg, &prefix[0x30], hmac_key) != 0) {
		goto err;
	}

	hmac_sha256(hmac_key, 0x20, prefix, pref_len - 0x20, mac1);
	if(memcmp_ct(mac1, &prefix[pref_len-0x20], 0x20) != 0) {
		ERR("invalid file");
		goto err;
	}

	SHA256_CTX kctx;
	sha256_init(&kctx);
	sha256_update(&kctx, symm_key, 0x20);
	sha256_update(&kctx, &prefix[0x10], 0x20);
	sha256_final(&kctx, enc_key);

	payload = malloc(payload_len);
	if(payload == NULL) {
		ERR("failed to allocate memory");
		goto err;
	}

	if(fread(payload, 1, payload_len, ff) != payload_len) {
		goto readerr;
	}
	if(fread(mac2f, 1, 0x20, ff) != 0x20) {
		goto readerr;
	}

	HMAC_SHA256_CTX hctx;
	hmac_sha256_init(&hctx, hmac_key, 0x20);
	hmac_sha256_update(&hctx, prefix, pref_len);
	hmac_sha256_update(&hctx, payload, payload_len);
	hmac_sha256_final(&hctx, mac2c);

	if(memcmp_ct(mac2c, mac2f, 0x20) != 0) {
		ERR("invalid file");
		goto err;
	}

	chacha_dec(enc_key, 0x20, 0, payload, payload, payload_len);

	void **cur = data;
	uint8_t *ptr = payload;
	uint64_t i;
	for(i = 0; (ptr - payload) < payload_len && i < payload_num; i++) {
		ptr = f->dataread(cur, arg, ptr);
		if(ptr == NULL) {
			goto err;
		}

		cur = (void **) ((char*)(*cur) + f->next_off);
	}
	*cur = NULL;
	if(i != payload_num) {
		ERR("read num does not match expected");
		goto err;
	}
	if(ptr - payload != payload_len) {
		ERR("read length does not match expected");
		goto err;
	}

	ret = 0;

err:
	if(ff) fclose(ff);
	if(payload) zfree(payload, payload_len);
	memsets(enc_key, 0, sizeof(enc_key));
	memsets(symm_key, 0, sizeof(symm_key));
	memsets(hmac_key, 0, sizeof(hmac_key));

	return ret;

readerr:
	ERR("failed to read from file: %s", path);
	goto err;

}

