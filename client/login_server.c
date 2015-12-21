#include <stdio.h>
#include <stdlib.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/endian.h>
#include <libibur/util.h>

#include "login_server.h"
#include "account.h"
#include "connect_server.h"
#include "ibchat_client.h"
#include "uname.h"

#include "../crypto/crypto_layer.h"
#include "../util/line_prompt.h"
#include "../util/defaults.h"
#include "../util/log.h"

static int send_login_message(struct con_handle *ch, struct account *acc, RSA_KEY *rkey, struct keyset *keys) {
	struct message *challenge = NULL;
	uint8_t *resp = NULL;
	int ret = 0;

	challenge = recv_message(ch, keys, 0);
	if(challenge == NULL) {
		goto err;
	}

	if(challenge->length != 0x20) {
		ERR("invalid challenge message from server");
		goto err;
	}

	uint64_t bits = decbe64(acc->key_bin);

	uint64_t size = 0;
	size += 0x20;
	size += rsa_pubkey_bufsize(bits);
	size += 0x20;
	size += 0x08;
	size += (bits + 7) / 8;
	resp = malloc(size);

	uint8_t *uid_b, *pkey_b, *chn_b, *sigl_b, *sig_b;
	uid_b = resp;
	pkey_b = uid_b + 0x20;
	chn_b = pkey_b + rsa_pubkey_bufsize(bits);
	sigl_b = chn_b + 0x20;
	sig_b = sigl_b + 8;

	sha256((uint8_t *)acc->uname, acc->u_len + 1, uid_b);
	if(rsa_wire_prikey2pubkey(acc->key_bin, acc->k_len, pkey_b,
		rsa_pubkey_bufsize(bits)) != 0) {
		goto err;
	}
	memcpy(chn_b, challenge->message, 0x20);
	encbe64((bits + 7) / 8, sigl_b);

	if(rsa_pss_sign(rkey, resp, sig_b - resp, sig_b, (bits + 7) / 8) != 0) {
		ERR("failed to sign message");
		goto err;
	}

	if(send_message(ch, keys, resp, size) != 0) {
		ERR("failed to send message");
		goto err;
	}

	goto cleanup;
err:
	ret = -1;
cleanup:
	if(challenge) free_message(challenge);
	if(resp) zfree(resp, size);

	return ret;
}

int get_server_authresponse(struct con_handle *ch, struct keyset *keys) {
	struct message *authresponse = NULL;

	/* wait for 5 seconds, that should be long enough */
	authresponse = recv_message(ch, keys, 5000000ULL);
	if(authresponse == NULL) {
		return -1;
	}

	if(authresponse->length != 8 ||
		memcmp("cliauth", authresponse->message, 7) != 0 ||
		(authresponse->message[7] > 4) != 0) {
		ERR("server sent invalid authorization response");

		free_message(authresponse);
		return -1;
	}
	int val = authresponse->message[7];

	free_message(authresponse);
	return val;
}

static int prompt_verify_skey(struct account *acc, RSA_PUBLIC_KEY *key, int firsttime) {
	uint64_t len = rsa_pubkey_bufsize(key->bits);
	uint8_t *pkey_bin = malloc(len);
	if(pkey_bin == NULL) {
		return -1;
	}

	uint8_t hash[32];

	rsa_pubkey2wire(key, pkey_bin, len);

	sha256(pkey_bin, len, hash);

	free(pkey_bin);

	if(memcmp_ct(hash, acc->sfing, 32) == 0) {
		/* the key is already correct */
		return 0;
	}

	char hexhash[65];
	to_hex(hash, 32, hexhash);
	hexhash[64] = '\0';

	if(firsttime) {
		printf("server at %s provided public key with fingerprint:\n"
		"%s\n"
		"you should check this fingerprint against a separate trustworthy source\n"
		"trust this key? [y/n] ",
		acc->addr, hexhash);
	} else {
		char ohexhash[65];
		to_hex(acc->sfing, 32, ohexhash);
		ohexhash[64] = '\0';
		printf("server at %s provided public key with fingerprint:\n"
		"%s\n"
		"this does not match the previous fingerprint of:\n"
		"%s\n"
		"you should check this fingerprint against a separate trustworthy source\n"
		"trust this key? [y/n] ",
		acc->addr, hexhash, ohexhash);
	}

	int resp = yn_prompt();
	if(resp == -1) {
		return -1;
	}

	if(resp == 1) {
		memcpy(acc->sfing, hash, 32);
		return firsttime ? 0 : 1;
	} else {
		return -1;
	}
}

int create_account(struct account *acc, struct server_connection *sc) {
	RSA_KEY rsa_key;
	char *uname = NULL;
	char *addr = NULL;

	rsa_key.p = BN_ZERO;
	rsa_key.q = BN_ZERO;
	rsa_key.n = BN_ZERO;
	rsa_key.d = BN_ZERO;

	memset(acc, 0, sizeof(*acc));

	/* initialize to zero so we can free it later without worrying */

	printf("generating identity key\n");

	if(rsa_gen_key(&rsa_key, 2048, 65537) != 0) {
		ERR("failed to generate identity key");
		goto err;
	}

	uname = getusername(NULL, stdout);
	if(uname == NULL) {
		ERR("failed to read username");
		goto err;
	}

	printf("server address [leave empty for default]: ");
	addr = line_prompt(NULL, NULL, 0);
	if(addr == NULL) {
		ERR("failed to read input");
		goto err;
	}

	if(strcmp(addr, "") == 0) {
		free(addr);
		addr = strdup(DFLT_ADDR);

		if(addr == NULL) {
			ERR("failed to duplicate string");
			return -1;
		}
	}

	/* populate the account struct */
	acc->u_len = strlen(uname);
	acc->a_len = strlen(addr);
	acc->k_len = rsa_prikey_bufsize(rsa_key.bits);

	acc->uname = uname;
	acc->addr = addr;
	acc->key_bin = malloc(acc->k_len);
	/* with the write size key 2 wire will never fail */
	rsa_prikey2wire(&rsa_key, acc->key_bin, acc->k_len);

	/* we need to connect to the server to register */
	int ret = connect_server(addr, &(sc->ch), &(sc->server_key), &(sc->keys));
	if(ret != 0) {
		goto err;
	}

	/* we need to check the key, prompt the user to verify it elsewhere */
	ret = prompt_verify_skey(acc, &sc->server_key, 1);
	if(ret != 0) {
		if(ret == -1) {
			ERR("failed to authenticate server key");
		}
		goto serr;
	}

	/* now that we're connected we need to ask to register */
	if(send_login_message(sc->ch, acc, &rsa_key, &sc->keys) != 0) {
		ERR("failed to send login message to server");
		goto serr;
	}

	/* get the response */
	int servresp = get_server_authresponse(sc->ch, &sc->keys);
	if(servresp == -1) {
		ERR("failed to get authorization response from server");
		goto serr;
	}

	switch(servresp) {
	case 0:
	case 2:
		printf("server claims to have you already registered\n"
			"either your random number generator is compromised\n"
			"or the server cannot be trusted.\n"
			"exiting.\n");
		goto serr;
	case 3:
		printf("a user with that username already exists on that server.\n");
		goto serr;
	case 4:
		printf("a server error occurred, could not register.\n");
		goto serr;
	case 1:
		break;
	}
	if(servresp != 1) {
		ERR("programmatic error occurred");
		goto serr;
	}

	printf("registering user %s at %s\n", acc->uname, acc->addr);
	if(send_message(sc->ch, &sc->keys, (uint8_t*) "register", 8) != 0) {
		ERR("failed to send registration message");
		goto serr;
	}

	if(init_account_file(acc) != 0) {
		ERR("failed to init account file");
		goto serr;
	}

	return 0;
serr:
	cleanup_server_connection(sc);
err:
	if(uname) free(uname);
	if(addr) free(addr);
	if(acc->key_bin) free(acc->key_bin);
	rsa_free_prikey(&rsa_key);

	return -1;
}

int login_account(struct account *acc, struct server_connection *sc) {
	RSA_KEY rsa_key;
	if(rsa_wire2prikey(acc->key_bin, acc->k_len, &rsa_key) != 0) {
		ERR("failed to expand identity key");
		return 1;
	}

	/* we need to connect to the server to register */
	int ret = connect_server(acc->addr, &(sc->ch), &(sc->server_key), &(sc->keys));
	if(ret != 0) {
		goto err;
	}

	/* we need to check the key, prompt the user to verify it elsewhere */
	ret = prompt_verify_skey(acc, &sc->server_key, 0);
	if(ret != 0) {
		if(ret == -1) {
			ERR("failed to authenticate server key");
			goto serr;
		}
		if(ret == 1) {
			printf("saving new server key fingerprint\n");
			userfile_dirty = 1;
		}
	}

	/* now that we're connected we need to ask to register */
	if(send_login_message(sc->ch, acc, &rsa_key, &sc->keys) != 0) {
		ERR("failed to send login message to server");
		goto serr;
	}

	/* get the response */
	int servresp = get_server_authresponse(sc->ch, &sc->keys);
	if(servresp == -1) {
		ERR("failed to get authorization response from server");
		goto serr;
	}

	switch(servresp) {
	case 0:
		break;
	case 1:
		printf("the server does not have your account registered.\n"
		       "would you like to register? [y/n] ");
		break;
	case 2:
		printf("your account is already logged in to this server.\n"
		       "the other instance must be logged out before you can log in.\n");
		goto serr;
	case 3:
		printf("there is a different user registered under this name on this server.\n"
		       "if you believe this is an error, contact the server administrator.\n");
		goto serr;
	case 4:
		printf("a server error occurred, could not login.\n");
		goto serr;
	}
	if(servresp != 1 && servresp != 0) {
		ERR("programmatic error occurred");
		goto serr;
	}
	if(servresp == 1) {
		int resp = yn_prompt();
		if(resp != 1) {
			goto serr;
		}
		printf("registering user %s at %s\n", acc->uname, acc->addr);

		if(send_message(sc->ch, &sc->keys, (uint8_t*) "register", 8) != 0) {
			ERR("failed to send registration message");
			goto serr;
		}
	}

	printf("user %s logged in to %s\n", acc->uname, acc->addr);

	return 0;
serr:
	cleanup_server_connection(sc);
err:
	rsa_free_prikey(&rsa_key);

	return -1;
	//TODO this -- note to self: leave better comments in the future
	return 1;
}

void cleanup_server_connection(struct server_connection *sc) {
	memsets(&(sc->keys), 0, sizeof(struct keyset));

	end_handler(sc->ch);
}

