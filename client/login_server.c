#include <stdio.h>
#include <stdlib.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/endian.h>
#include <libibur/util.h>

#include "../util/defaults.h"

#include "login_server.h"
#include "account.h"
#include "connect_server.h"

#include "../util/line_prompt.h"

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
		"this does not match the previous fingerprint of %s\n"
		"you should check this fingerprint against a separate trustworthy source\n"
		"trust this key? [y/n] ",
		acc->addr, hexhash, ohexhash);
	}

	char *resp = line_prompt(NULL, NULL, 0);
	if(resp == NULL) {
		fprintf(stderr, "failed to read response\n");
		return -1;
	}

	if(resp[0] == 'y') {
		memcpy(acc->sfing, hash, 32);
		return 0;
	} else {
		return 1;
	}
}

int create_account(struct account *acc, struct server_connection *sc) {
start:;
	RSA_KEY rsa_key;
	char *uname = NULL;
	char *addr = NULL;

	rsa_key.p = BN_ZERO;
	rsa_key.q = BN_ZERO;
	rsa_key.n = BN_ZERO;
	rsa_key.d = BN_ZERO;

	/* initialize to zero so we can free it later without worrying */

	printf("generating identity key\n");

	if(rsa_gen_key(&rsa_key, 2048, 65537) != 0) {
		fprintf(stderr, "failed to generate identity key\n");
		goto err;
	}

	printf("username: ");
	uname = line_prompt(NULL, NULL, 0);
	if(uname == NULL) {
		fprintf(stderr, "failed to read username\n");
		goto err;
	}

	printf("server address [leave empty for default]: ");
	addr = line_prompt(NULL, NULL, 0);
	if(addr == NULL) {
		fprintf(stderr, "failed to read input\n");
		goto err;
	}

	if(strcmp(addr, "") == 0) {
		free(addr);
		addr = strdup(DFLT_ADDR);

		if(addr == NULL) {
			fprintf(stderr, "failed to duplicate string\n");
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
		printf("try again? [y/n] ");
		char *resp = line_prompt(NULL, NULL, 0);
		if(resp == NULL) {
			fprintf(stderr, "failed to read input\n");
			goto err;
		}

		if((resp[0] | 32) != 'y') {
			goto err;
		}

		if(rsa_free_prikey(&rsa_key) != 0) {
			fprintf(stderr, "failed to free identity key\n");
			goto err;
		}
		free(uname);
		free(addr);
		free(resp);
		goto start;
	}

	/* we need to check the key, prompt the user to verify it elsewhere */
	if(prompt_verify_skey(acc, &(sc->server_key), 1) != 0) {
		goto serr;
	}

	/* now that we're connected we need to ask to register */
	//if(send_login_message(&(sc->ch), &(sc->keys)) != 0) {
	//	fprintf(stderr, "failed to send login message to server\n");
	//	return -1;
	//}

	return 0;
serr:
	cleanup_server_connection(sc);
err:
	if(uname) free(uname);
	if(addr) free(addr);

	return -1;
}

void cleanup_server_connection(struct server_connection *sc) {
	memsets(&(sc->keys), 0, sizeof(struct keyset));

	end_handler(&(sc->ch));
}

