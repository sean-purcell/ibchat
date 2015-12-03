#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <ibcrypt/sha256.h>
#include <ibcrypt/rsa_util.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "../util/lock.h"
#include "../util/line_prompt.h"

#include "cli.h"
#include "account.h"
#include "profile.h"
#include "connect_server.h"
#include "ibchat_client.h"
#include "login_server.h"
#include "friends.h"
#include "notifications.h"
#include "bg_manager.h"
#include "conversation.h"
#include "friendreq.h"

struct profile prof;
struct account *acc;
struct server_connection sc;

struct notif *notifs;

struct lock lock;

/* 0: default mode, 1: in conversation, 2: in friendreq, -1: stop */
int mode;

int stop;

static char keysig[65];

int init();
int select_profile();
int handle_user();

int main(int argc, char **argv) {
	/* initialize variables, etc. */
	if(init() != 0) {
		fprintf(stderr, "failed to initialize ibchat client\n");
		return 1;
	}

	/* log the user in */
	if(login_profile(NULL, &prof) != 0) {
		fprintf(stderr, "failed to login\n");
		return 1;
	}

	if(select_profile() != 0) {
		return 1;
	}

	if(handle_user() != 0) {
		return 1;
	}

	/* TODO: disconnect and clean up */

	return 0;
}

int select_profile() {
	int ret;
	if((ret = pick_account(&prof, &acc)) < 0) {
		fprintf(stderr, "failed to pick account\n");
		return 1;
	}
	if(ret == 1) {
		printf("there are no accounts to use, exiting.\n");
		return 1;
	}

	if(ret == 0x55) { /* register a new account */
		acc = malloc(sizeof(*acc));
		if(acc == NULL) {
			fprintf(stderr, "failed to allocate memory\n");
			return 1;
		}
		if(create_account(acc, &sc) != 0) {
			fprintf(stderr, "failed to register account\n");
			return 1;
		}

		/* we should write the user file again */
		if(add_account(&prof, acc) != 0) {
			fprintf(stderr, "failed to add account to user file\n");
			return 1;
		}
	} else { /* login an existing account */
		if(login_account(acc, &sc) != 0) {
			fprintf(stderr, "failed to login account\n");
			return 1;
		}

		if(check_userfile(&prof) != 0) {
			return 1;
		}

		/* load the friend file */
		if(read_friendfile(acc) != 0) {
			fprintf(stderr, "failed to read friend file\n");
			return 1;
		}
	}

	return 0;
}

int handler_init();
int handler_select();

int handle_user() {
	if(!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
		fprintf(stderr, "ibchat must be run in a tty\n");
		return 1;
	}

	if(handler_init() != 0) {
		return 1;
	}

	while(handler_status(sc.ch) == 0 && stop == 0) {
		/* print status and options */
		handler_select();
	}
	if(handler_status(sc.ch) != 0) {
		printf("server disconnected\n");
	}
	set_mode(-1);
	printf("exiting\n");
	return 0;
}

int handler_init() {
	stop = 0;
	mode = 0;
	if(init_lock(&lock) != 0) {
		return 1;
	}

	{
		uint64_t keylen = rsa_pubkey_bufsize(decbe64(acc->key_bin));
		uint8_t *pkey = malloc(keylen);
		if(pkey == NULL) {
			fprintf(stderr, "failed to allocate memory\n");
			return 1;
		}
		if(rsa_wire_prikey2pubkey(acc->key_bin, acc->k_len,
			pkey, keylen) != 0) {
			fprintf(stderr, "failed to convert key to public\n");
			return 1;
		}
		uint8_t hash[32];
		sha256(pkey, keylen, hash);
		to_hex(hash, 32, keysig);

		free(pkey);
	}

	/* we should spawn the manager thread here */
	if(start_bg_thread(&sc) != 0) {
		return 1;
	}

	return 0;
}

int handler_select() {
	int notiflen = notiflist_len(notifs);

	printf("user: %s\n"
		"fingerprint: %s\n",
		acc->uname,
		keysig);

	printf("%1d: message friend\n", 1);
	printf("%1d: view %d notification(s)\n", 2, notiflen);
	printf("%1d: add friend\n", 3);
	printf("%1d: exit\n", 0);

	uint64_t sel = num_prompt("selection", 0, 3);

	if(get_mode() != 0) {
		return 0;
	}
	switch(sel) {
	case 0:
		stop = 1; break;
	case 1:
		if(select_conversation(acc) != 0) {
			stop = 1;
		}
		break;
	case 3:
		if(send_friendreq(&sc, acc) != 0) {
			stop = 1;
		}
		break;
	default:
		fprintf(stderr, "error occurred in selection\n");
		stop = 1;
		break;
	}

	return 0;
}

void set_mode(int v) {
	acquire_writelock(&lock);
	set_mode_no_lock(v);
	release_writelock(&lock);
}

void set_mode_no_lock(int v) {
	mode = v;
}

int get_mode() {
	acquire_readlock(&lock);
	int v = mode;
	release_readlock(&lock);
	return v;
}

