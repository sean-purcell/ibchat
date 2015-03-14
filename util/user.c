#include <stdint.h>

#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/endian.h>

#include "user.h"

uint64_t uid_hash(uint8_t salt[32], uint8_t uid[32]) {
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

