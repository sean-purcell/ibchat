#include <stdint.h>

#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/endian.h>

#include "user.h"

static int valid_uname_char(char c) {
	return
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		(c == '_');
}

int valid_uname(char *uname, size_t ulen) {
	int invalid = 0;
	size_t i;
	for(i = 0; i < ulen; i++) {
		invalid |= !(valid_uname_char(uname[i]));
	}

	return !invalid;
}

void gen_uid(char *uname, size_t ulen, uint8_t uid[32]) {
	SHA256_CTX ctx;
	const uint8_t zero = 0;

	sha256_init(&ctx);
	sha256_update(&ctx, (uint8_t*)uname, ulen);
	sha256_update(&ctx, &zero, 1);
	sha256_final(&ctx, uid);
}

void uid_hash(uint8_t salt[32], uint8_t uid[32], uint8_t hash[32]) {
	hmac_sha256(salt, 32, uid, 32, hash);
}

uint64_t uid_hash_val(uint8_t salt[32], uint8_t uid[32]) {
	uint8_t hash[32];

	hmac_sha256(salt, 32, uid, 32, hash);

	uint64_t ret =
		decbe64(&hash[ 0]) ^
		decbe64(&hash[ 8]) ^
		decbe64(&hash[16]) ^
		decbe64(&hash[24]);

	memsets(hash, 0, 32);

	return ret;
}

