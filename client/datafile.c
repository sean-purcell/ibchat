#include <stdio.h>
#include <stdint.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/rand.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/endian.h>

int write_datafile(char *path, uint8_t *symm_key, uint8_t *hmac_key,
	void *data, size_t next_off,
	uint64_t (*f_datalen)(void *), uint8_t *(*f_datawrite)(void *, uint8_t *)) {

	int ret = -1;

	uint8_t *payload = NULL;
	uint64_t payload_len = 0;
	uint64_t payload_num = 0;

	uint8_t enc_key[0x20];

	FILE *ff = fopen(path, "wb");
	if(ff == NULL) {
		fprintf(stderr, "failed to open file for writing: %s\n", path);
		goto err;
	}

	uint8_t prefix[0x50];

	encbe64(payload_num, &prefix[0]);
	encbe64(payload_len, &prefix[8]);
	if(cs_rand(&prefix[0x10], 0x20) != 0) {
		fprintf(stderr, "failed to generate random numbers\n");
	}
	hmac_sha256(hmac_key, 0x20, prefix, 0x30, &prefix[0x30]);

	SHA256_CTX kctx;
	sha256_init(&kctx);
	sha256_update(&kctx, symm_key, 0x20);
	sha256_update(&kctx, &prefix[0x10], 0x20);
	sha256_final(&kctx, enc_key);

	void *cur = data;
	while(cur) {
		payload_len += f_datalen(cur);
		payload_num++;

		cur = *((void **) ((char*)cur + next_off));
	}

	payload = malloc(payload_len);
	if(payload == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		goto err;
	}

	cur = data;
	uint8_t *ptr = payload;
	while(cur) {
		ptr = f_datawrite(cur, ptr);
		if(ptr == NULL) {
			goto err;
		}

		cur = *((void **) ((char*)cur + next_off));
	}
	if(ptr - payload != payload_len) {
		fprintf(stderr, "written length does not match expected\n");
	}

	chacha_enc(enc_key, 0x20, 0, payload, payload, payload_len);

	HMAC_SHA256_CTX hctx;
	hmac_sha256_init(&hctx, hmac_key, 0x20);
	hmac_sha256_update(&hctx, prefix, sizeof(prefix));
	hmac_sha256_update(&hctx, payload, payload_len);

	uint8_t mac[0x20];
	hmac_sha256_final(&hctx, mac);

	if(fwrite(prefix, 1, sizeof(prefix), ff) != sizeof(prefix)) {
		goto writerr;
	}
	if(fwrite(payload, 1, payload_len, ff) != payload_len) {
		goto writerr;
	}
	if(fwrite(mac, 1, 0x20, ff) != 0x20) {
		goto writerr;
	}

	ret = 0;

err:
	if(ff) fclose(ff);
	if(payload) zfree(payload, payload_len);
	memsets(enc_key, 0, sizeof(enc_key));

	return ret;

writerr:
	fprintf(stderr, "failed to write to file: %s\n", path);
	goto err;
}

