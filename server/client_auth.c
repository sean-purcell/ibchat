#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/rand.h>
#include <ibcrypt/bignum.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "client_auth.h"

#include "../crypto/crypto_layer.h"
#include "../inet/protocol.h"
#include "../inet/message.h"
#include "../util/log.h"

#include "client_handler.h"
#include "user_db.h"

static int check_user(uint8_t *uid, RSA_PUBLIC_KEY *pkey) {
	struct user *u = user_db_get(uid);
	if(u == NULL) {
		return 1;
	}

	/* compare the public keys */
	{
		uint64_t ret = 0;
		ret |= (pkey->bits - u->pkey.bits);
		ret |= (pkey->e - u->pkey.e);

		ret |= bno_cmp(&pkey->n, &u->pkey.n);

		if(ret != 0) {
			return 3;
		}
	}

	/* now check if the user is already logged in */
	if(get_handler(uid) != NULL) {
		return 2;
	}

	return 0;
}

static int prompt_user_register(struct con_handle *con_hndl, struct keyset *keys) {
	struct message *resp = recv_message(con_hndl, keys, 0);

	if(resp == NULL) {
		return -1;
	}

	if(resp->length != 8 || memcmp(resp->message, "register", 8) != 0) {
		free_message(resp);
		return 1;
	}

	free_message(resp);

	return 0;
}

static int user_register(uint8_t *uid, RSA_PUBLIC_KEY *pkey, int fd, struct con_handle *con_hndl, struct keyset *keys) {
	int ret = prompt_user_register(con_hndl, keys);
	if(ret != 0) {
		return ret;
	}

	/* add them to the user database */
	struct user u;
	if(user_init(uid, *pkey, &u) != 0) {
		return -1;
	}

	if(user_db_add(u) != 0) {
		return -1;
	}

	char uname[65];
	to_hex(uid, 32, uname);
	uname[64] = '\0';
	LOG("%d: registered user %s", fd, uname);
	return 0;
}

int auth_user(struct client_handler *cli_hndl, struct con_handle *con_hndl, struct keyset *keys, uint8_t *uid) {
#define ERR(x) ERR("%d: %s", cli_hndl->fd, x)

	uint8_t challenge[0x20];

	struct message *cli_response;

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
	/* we should wait arbitrarily long for the response as long as the client
	 * stays connected.  they could be verifying the server's key. */

	/* handle response */
	{
		cli_response = recv_message(con_hndl, keys, 0);
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
		rsa_pss_verify(&pb_key, sig_bin, siglen, cli_response->message, 0x20 + keylen + 0x20 + 0x08, &valid);

		if(!valid) {
			ERR("invalid signature");
			goto err3;
		}

		memcpy(uid, cli_response->message, 0x20);
	}

	/* now we have a uid and public key, identify this user */
	int ret = check_user(uid, &pb_key);

	char msg[8];
	memcpy(msg, "cliauth", 7);
	msg[7] = ret;

	if(send_message(con_hndl, keys, (uint8_t *) msg, 8) != 0) {
		goto err3;
	}

	if(ret == 2 || ret == 3) {
		if(ret == 2) {
			LOG("%d: user already logged in", cli_hndl->fd);
		} else {
			LOG("%d: user exists with different public key", cli_hndl->fd);
		}
		goto err3;
	}

	if(ret == 1) {
		ret = user_register(uid, &pb_key, cli_hndl->fd, con_hndl, keys);
		if(ret != 0) {
			if(ret == -1) {
				ERR("failed to register user");
			}
			goto err3;
		}
	}

	char buf[65];
	to_hex(uid, 32, buf);
	LOG("%d: logged in user %s", cli_hndl->fd, buf);

	memset(challenge, 0, sizeof(challenge));

	rsa_free_pubkey(&pb_key);
	free_message(cli_response);

	return 0;

err3:
	rsa_free_pubkey(&pb_key);
err2:
	free_message(cli_response);
err1:
	memset(challenge, 0, sizeof(challenge));
	memset(uid, 0, sizeof(0x20));
	return -1;
}

