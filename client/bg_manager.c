#include <stdio.h>

#include <sys/time.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "bg_manager.h"
#include "login_server.h"
#include "cli.h"
#include "friendreq.h"

pthread_t bg_manager;

pthread_mutex_t bg_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t bg_wait  = PTHREAD_COND_INITIALIZER;

#define WAITTIME ((uint64_t) 100000ULL)

static int parse_friendreq(uint8_t *sender, uint8_t *payload, uint64_t p_len);

int add_umessage(struct message *m) {
	uint8_t *sender = &m->message[0x01];
	uint8_t *payload = &m->message[0x29];
	uint8_t type = m->message[0x29];

	char s_hex[65];
	to_hex(sender, 0x20, s_hex);

	fprintf(lgf, "message from %s of length %llu\n", s_hex, m->length);

	uint64_t p_len = decbe64(&m->message[0x21]);

	/* check the lengths */
	if(p_len + 0x29 != m->length) {
		/* server lying is a crashing error */
		return -1;
	}

	switch(type) {
	case 0:
		/* typical message from friend */
		fprintf(stderr, "NOT IMPLEMENTED: %s:%d\n", __FILE__, __LINE__);
		return -1;
		break;
	case 1:
		/* friend request */
		parse_friendreq(sender, payload, p_len);
	}

	return 0;
}

static int parse_friendreq(uint8_t *sender, uint8_t *payload, uint64_t p_len) {
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

int add_pkeyresp(struct message *m) {
	pthread_mutex_lock(&bg_lock);
	if(get_mode() != 2) {
		pthread_mutex_unlock(&bg_lock);
		return -1;
	}

	pkey_resp = m;
	pthread_cond_broadcast(&bg_wait);
	pthread_mutex_unlock(&bg_lock);
	return 0;
}

int add_unotfound(struct message *m) {
	pthread_mutex_lock(&bg_lock);
	if(get_mode() != 2) {
		pthread_mutex_unlock(&bg_lock);
		return -1;
	}

	pkey_resp = m;
	pthread_cond_broadcast(&bg_wait);
	pthread_mutex_unlock(&bg_lock);
	return 0;
}

void *background_thread(void *_arg) {
	struct server_connection *sc = (struct server_connection *) _arg;

	while(get_mode() != -1) {
		struct message *m = recv_message(sc->ch, &sc->keys, WAITTIME);
		if(handler_status(sc->ch) != 0) {
			set_mode(-1);
		}
		if(m == NULL) continue;

		int ret = 0;
		switch(m->message[0]) {
		case 0:
			ret = add_umessage(m);
			break;
		case 1:
			ret = add_pkeyresp(m);
			break;
		case 0xff:
			ret = add_unotfound(m);
			break;
		}
		if(ret != 0) {
			break;
		}
	}

	fprintf(stderr, "background thread crashed\n");
	acquire_writelock(&lock);
	stop = 1;
	release_writelock(&lock);

	set_mode(-1);
	pthread_cond_broadcast(&bg_wait);

	return NULL;
}

int start_bg_thread(struct server_connection *sc) {
	if(pthread_create(&bg_manager, NULL, background_thread, sc) != 0) {
		fprintf(stderr, "failed to start background thread\n");
		return -1;
	}

	return 0;
}

