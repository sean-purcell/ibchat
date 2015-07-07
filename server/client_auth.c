#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/rand.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "../crypto/crypto_layer.h"
#include "../inet/protocol.h"
#include "../inet/message.h"

#include "client_handler.h"

int check_user(uint8_t *uid, RSA_PUBLIC_KEY *pkey) {
	return 0;
}

int auth_user(struct client_handler *cli_hndl, struct con_handle *con_hndl, struct keyset *keys) {
#define ERR(x) fprintf(stderr, "%d: %s\n", cli_hndl->fd, x)

	uint8_t challenge[0x20];

	struct message *cli_response;

	uint8_t uid[0x20];
	RSA_PUBLIC_KEY pb_key;

	/* generate 256 bit challenge numbers and send them */
	{
		if(cs_rand(challenge, 0x20) != 0) {
			/* failed to generate random numbers, we should exit */
			/* TODO: make this more severe */
			ERR("generating random numbers failed, exit ASAP");
			goto err1;
		}

		if(send_message(con_hndl, keys, challenge, 0x20) != 0) {
			ERR("failed to allocate message");
			goto err1;
		}
	}

	/* now we wait for the response */
	/* we shouldn't wait more than 10 seconds, the client shouldn't be busy */

	/* handle response */
	{
		cli_response = recv_message(con_hndl, keys, 10000000ULL);
		if(cli_response == NULL) {
			ERR("no auth response");
			goto err1;
		}

		uint8_t *pb_key_bin = &cli_response->message[0x20];
		uint64_t keylen = rsa_pubkey_bufsize(decbe64(pb_key_bin));

		if(0x20 + keylen + 0x20 + 0x08 >= cli_response->length) {
			/* invalid message, exit now */
			ERR("invalid length message");
			goto err2;
		}

		/* check the challenge bits */
		uint8_t *challenge_cli = &cli_response->message[0x20 + keylen];

		if(memcmp_ct(challenge, challenge_cli, 0x20) != 0) {
			ERR("invalid challenge bytes");
			goto err2;
		}

		uint8_t *sig_bin = &cli_response->message[0x20 + keylen + 0x20 + 0x08];
		uint64_t siglen = decbe64(&cli_response->message[0x20 + keylen + 0x20]);

		if(0x20 + keylen + 0x20 + 0x08 + siglen != cli_response->length) {
			/* invalid message, exit now */
			ERR("invalid length message");
			goto err2;
		}

		/* now parse the public key */
		if(rsa_wire2pubkey(pb_key_bin, keylen, &pb_key) != 0) {
			/* failed to read key, we should exit */
			ERR("failed to read public key");
			goto err2;
		}

		/* now check the signature */
		int valid = 0;
		rsa_pss_verify(&pb_key, sig_bin, siglen, cli_response->message, 0x20 + keylen + 0x08, &valid);

		if(!valid) {
			ERR("invalid signature");
			goto err3;
		}

		memcpy(uid, cli_response->message, 0x20);
	}

	/* now we have a uid and public key, identify this user */
	int ret = check_user(uid, &pb_key);

	switch(ret) {
	case 0:
		break;
	case 1:
		break;
	case 2:
		break;
	case 3:
		break;
	}

	memset(challenge, 0, sizeof(challenge));
	memset(uid, 0, sizeof(uid));

	rsa_free_pubkey(&pb_key);
	free_message(cli_response);

	return 0;

err3:
	rsa_free_pubkey(&pb_key);
err2:
	free_message(cli_response);
err1:
	memset(challenge, 0, sizeof(challenge));
	memset(uid, 0, sizeof(uid));
	return -1;
}

