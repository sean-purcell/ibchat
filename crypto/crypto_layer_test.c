#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <ibcrypt/rand.h>

#include <libibur/util.h>

#include "crypto_layer.h"

int main() {
	const size_t key_size = 128;
	uint8_t keybuf[key_size];
	struct keyset skey;
	struct keyset rkey;

	/* generate the keys */
	if(cs_rand(keybuf, key_size) != 0) {
		return -1;
	}

	memcpy(skey.send_symm_key, &keybuf[0x00], 0x20);
	memcpy(skey.recv_symm_key, &keybuf[0x20], 0x20);
	memcpy(skey.send_hmac_key, &keybuf[0x40], 0x20);
	memcpy(skey.recv_hmac_key, &keybuf[0x60], 0x20);
	skey.nonce = 0;
	memcpy(rkey.send_symm_key, &keybuf[0x20], 0x20);
	memcpy(rkey.recv_symm_key, &keybuf[0x00], 0x20);
	memcpy(rkey.send_hmac_key, &keybuf[0x60], 0x20);
	memcpy(rkey.recv_hmac_key, &keybuf[0x40], 0x20);
	skey.nonce = 0;

	char *secret = "this is my secret.  there are many like it, but this one is mine.";
	struct message *m = encrypt_message(&skey, (uint8_t*)secret, strlen(secret) + 1);

	if(m == NULL) {
		printf("FAILED :C\n");
		return 1;
	}

	/* encrypted message: */
	printbuf(m->message, m->length);

	char out[256];
	int ret = decrypt_message(&rkey, m, (uint8_t*)out);
	free_message(m);
	printf("%d\n", ret);
	printf("%s\n", out);

	char *secret2 = "this is my secret.  there are many like it, like the one you just saw.";
	m = encrypt_message(&skey, (uint8_t*)secret2, strlen(secret2) + 1);

	if(m == NULL) {
		printf("FAILED :C\n");
		return 1;
	}

	printbuf(m->message, m->length);

	ret = decrypt_message(&rkey, m, (uint8_t*)out);
	printf("%d\n", ret);
	printf("%s\n", out);

	m->message[15] ^= 0x4;
	ret = decrypt_message(&rkey, m, (uint8_t*)out);
	printf("%d\n", ret);
}

