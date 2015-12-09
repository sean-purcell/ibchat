#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/rand.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/rsa.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "../util/line_prompt.h"
#include "../util/lock.h"

#include "cli.h"
#include "friendreq.h"
#include "uname.h"
#include "bg_manager.h"

static int send_pkey_req(struct server_connection *sc, uint8_t target[32]);
static int send_friendreq_message(struct server_connection *sc, struct account *acc, uint8_t target[32], uint8_t *pkey, uint64_t pkeylen);
static int verify_pkey(char *target, uint8_t *pkey_bin, uint64_t pkey_len);

int send_friendreq(struct server_connection *sc, struct account *acc) {
	int ret = 0;
	pkey_resp = NULL;

	/* prompt for a username */
	char *uname = getusername("friend name", stdout);
	if(uname == NULL) {
		fprintf(stderr, "failed to get friend name\n");
		return -1;
	}

	/* get the uid */
	uint8_t uid[32];
	sha256((uint8_t*)uname, strlen(uname) + 1, uid);

	if(send_pkey_req(sc, uid) != 0) {
		goto err;
	}

	set_mode(2);

	pthread_mutex_lock(&bg_lock);
	while(pkey_resp == NULL && get_mode() == 2) {
		pthread_cond_wait(&bg_wait, &bg_lock);
	}
	if(get_mode() == -1) {
		goto err;
	}
	set_mode(0);
	pthread_mutex_unlock(&bg_lock);

	if(pkey_resp->length < 0x21) {
		fprintf(stderr, "server returned invalid message\n");
		goto err;
	}

	if(pkey_resp->message[0] == 0xff) {
		printf("the server could not find the user you specified\n");
		goto end;
	}

	if(pkey_resp->length < 0x29) {
		fprintf(stderr, "server returned invalid message\n");
		goto err;
	}

	if(memcmp(&pkey_resp->message[1], uid, 32) != 0) {
		fprintf(stderr, "server returned public key for wrong user\n");
		goto err;
	}

	uint64_t pkeysize = rsa_pubkey_bufsize(decbe64(
		&pkey_resp->message[0x21]));

	if(pkeysize + 0x21 != pkey_resp->length) {
		fprintf(stderr, "server returned invalid message\n");
	}

	uint8_t *pkey_bin = &pkey_resp->message[0x21];

	/* verify the public key */
	int ver;
	if((ver = verify_pkey(uname, pkey_bin, pkeysize)) != 0) {
		if(ver == -1) {
			goto err;
		} else {
			goto end;
		}
	}

	if(send_friendreq_message(sc, acc, uid, pkey_bin, pkeysize) != 0) {
		goto err;
	}

	return 0;

	goto end;
err:
	ret = -1;
end:
	if(pkey_resp) free_message(pkey_resp);
	free(uname);
	return ret;
}

static int verify_pkey(char *target, uint8_t *pkey_bin, uint64_t pkey_len) {
	uint8_t hash[32];
	sha256(pkey_bin, pkey_len, hash);

	char hex[65];
	to_hex(hash, 32, hex);

	printf("please verify %s's public key fingerprint:\n"
		"%s\n"
		"does this match external verification? [y/n] ",
		target, hex);

	int ans = yn_prompt();
	if(ans == -1) {
		return -1;
	}
	if(ans == 0) {
		printf("friend request canceled\n");
		return 1;
	}

	return 0;
}

static int send_pkey_req(struct server_connection *sc, uint8_t target[32]) {
	uint8_t *message = malloc(1 + 0x20);
	if(message == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		return -1;
	}

	message[0] = 1;
	memcpy(&message[1], target, 0x20);

	if(send_message(sc->ch, &sc->keys, message, 0x21) != 0) {
		fprintf(stderr, "failed to send pkey request\n");
		return -1;
	}

	free(message);
	return 0;
}

static int send_friendreq_message(struct server_connection *sc,
	struct account *acc, uint8_t target[32], uint8_t *pkey,
	uint64_t pkeylen) {
	int ret = -1;

	uint64_t encblen = (decbe64(pkey) + 7) / 8;
	uint64_t siglen = (decbe64(acc->key_bin) + 7) / 8;

	uint64_t reqlen = 0;
	reqlen += 0x29; /* message type and destination/length */
	reqlen += 9; /* friend message prefix */
	reqlen += encblen; /* encrypted block */
	reqlen += 0x10; /* payload prefix */
	reqlen += acc->u_len; /* username */
	reqlen += rsa_pubkey_bufsize(decbe64(acc->key_bin)); /* pkey */
	reqlen += 0x20; /* MAC */
	reqlen += siglen; /* sig */
	uint8_t *reqbody = malloc(reqlen);
	if(reqbody == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		return -1;
	}

	RSA_KEY sig_key;
	memset(&sig_key, 0, sizeof(sig_key));
	RSA_PUBLIC_KEY rec_key;
	memset(&rec_key, 0, sizeof(rec_key));
	uint8_t *my_key = NULL;
	uint64_t my_keylen = rsa_pubkey_bufsize(decbe64(acc->key_bin));
	uint8_t keys[64];
	uint8_t *payload = NULL;
	uint64_t payloadlen = 0x10 + acc->u_len + my_keylen;

	uint8_t *ptr = reqbody;

	ptr[0] = 0; ptr++;
	memcpy(ptr, target, 0x20); ptr += 0x20;
	encbe64(reqlen - 0x29, ptr); ptr += 8;

	ptr[0] = 1; ptr++;
	encbe64(encblen, ptr); ptr += 8;
	encbe64(payloadlen + 0x20, ptr); ptr += 8;

	if(cs_rand(keys, 64) != 0) {
		fprintf(stderr, "failed to generate encryption keys\n");
		goto err;
	}

	if(rsa_wire2pubkey(pkey, pkeylen, &rec_key) != 0) {
		fprintf(stderr, "failed to expand public key\n");
		goto err;
	}

	if(rsa_oaep_encrypt(&rec_key, keys, 64, ptr, encblen) != 0) {
		fprintf(stderr, "failed to encrypt keys\n");
		goto err;
	}
	ptr += encblen;

	my_key = malloc(my_keylen);
	if((my_key = malloc(my_keylen)) == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		goto err;
	}
	if(rsa_wire_prikey2pubkey(acc->key_bin, acc->k_len,
		my_key, my_keylen) != 0) {
		fprintf(stderr, "failed to convert private key\n");
		goto err;
	}

	payload = ptr;

	encbe64(acc->u_len, &payload[0x00]);
	encbe64(my_keylen, &payload[0x08]);
	memcpy(&payload[0x10], acc->uname, acc->u_len);
	memcpy(&payload[0x10+acc->u_len], my_key, my_keylen);

	chacha_enc(&keys[0], 32, 0, payload, payload, payloadlen);
	hmac_sha256(&keys[32], 32, payload, payloadlen, &payload[payloadlen]);

	ptr += payloadlen + 0x20;

	if(rsa_wire2prikey(acc->key_bin, acc->k_len, &sig_key) != 0) {
		fprintf(stderr, "failed to expand private key\n");
		goto err;
	}
	if(rsa_pss_sign(&sig_key, reqbody, reqlen - siglen,
		ptr, siglen) != 0) {
		fprintf(stderr, "failed to sign\n");
		goto err;
	}

	if(send_message(sc->ch, &sc->keys, reqbody, reqlen) != 0) {
		fprintf(stderr, "failed to send message\n");
		goto err;
	}

	ret = 0;

err:;
	zfree(reqbody, reqlen);
	if(my_key) zfree(my_key, my_keylen);
	memsets(keys, 0, sizeof(keys));
	rsa_free_pubkey(&rec_key);
	rsa_free_prikey(&sig_key);

	return ret;
}

int parse_friendreq(uint8_t *sender, uint8_t *payload, uint64_t p_len) {
	int ret = -1, inv = -1;

	char s_hex[65];
	to_hex(sender, 0x20, s_hex);

	RSA_KEY rkey;
	memset(&rkey, 0, sizeof(rkey));

	RSA_PUBLIC_KEY pkey;
	memset(&pkey, 0, sizeof(pkey));

	uint8_t keys[64];
	uint8_t *symm = &keys[ 0];
	uint8_t *hmac = &keys[32];
	uint8_t mac[32];

	struct friendreq *freq = NULL;

	/* keyblock and datablock */
	uint64_t kb_len = decbe64(&payload[1]);
	uint64_t db_len = decbe64(&payload[9]);

	if(kb_len + db_len + 17 >= p_len) {
		fprintf(lgf, "invalid block lengths\n");
		goto inv;
	}

	/* expand the private key */
	if(rsa_wire2prikey(acc->key_bin, acc->k_len, &rkey) != 0) {
		fprintf(stderr, "failed to expand private key\n");
		goto err;
	}

	/* decrypt the message */
	if(rsa_oaep_decrypt(&rkey, &payload[0x11], kb_len, keys, 64) != 0) {
		fprintf(lgf, "invalid enc block\n");
		goto inv;
	}

	uint8_t *data = &payload[17 + kb_len];

	hmac_sha256(hmac, 32, data, db_len - 32, mac);
	if(memcmp_ct(mac, &data[db_len-32], 32) != 0) {
		fprintf(lgf, "invalid mac\n");
		goto inv;
	}

	chacha_dec(symm, 32, 0, data, data, db_len - 32);

	/* start building the friendreq struct */
	freq = malloc(sizeof(*freq));
	if(freq == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		goto err;
	}
	freq->u_len = decbe64(&data[0]);
	freq->k_len = decbe64(&data[8]);
	freq->uname = malloc(freq->u_len + 1);
	freq->pkey = malloc(freq->k_len + 1);

	if(freq->uname == NULL || freq->pkey == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		goto err;
	}

	memcpy(freq->uname, &data[16], freq->u_len);
	memcpy(freq->pkey, &data[16+freq->u_len], freq->k_len);

	uint64_t siglen = (decbe64(freq->pkey) + 7) / 8;

	if(p_len != kb_len + db_len + 17 + siglen) {
		goto inv;
	}

	/* now verify the message */
	if(rsa_wire2pubkey(freq->pkey, freq->k_len, &pkey) != 0) {
		fprintf(lgf, "failed to expand public key\n");
		goto inv;
	}

	int valid = 0;
	if(rsa_pss_verify(&pkey, &payload[p_len-siglen], siglen, payload,
		p_len-siglen, &valid) != 0) {
		goto inv;
	}
	if(!valid) {
		goto inv;
	}

	/* everything is valid, place it in the queue */
	struct notif *n = malloc(sizeof(struct notif));
	if(n == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		goto err;
	}

	n->type = 2;
	n->freq = freq;

	insert_notif(n);

end:
	ret = 0;
	inv = 0;
err:
	rsa_free_prikey(&rkey);
	rsa_free_pubkey(&pkey);
	memsets(keys, 0, sizeof(keys));
	memsets(mac, 0, sizeof(mac));
	if(ret || inv) free_friendreq(freq);
	return ret;
inv:
/* invalid message reject it but do not error */
	fprintf(lgf, "invalid friendreq from %s\n", s_hex);
	goto end;
}


void free_friendreq(struct friendreq *freq) {
	if(!freq) return;
	zfree(freq->uname, freq->u_len);
	zfree(freq->pkey, freq->k_len);
	zfree(freq, sizeof(*freq));
}

