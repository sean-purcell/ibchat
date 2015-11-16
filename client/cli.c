#include <stdio.h>
#include <unistd.h>

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

struct profile prof;
struct account acc;
struct server_connection sc;

struct notif *notifs;

struct lock lock;

/* 0: default mode, 1: in conversation, 2: in friendreq, -1: stop */
int mode;

int stop;

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

	if(ret == 0x55) { /* register a new account */
		if(create_account(&acc, &sc) != 0) {
			fprintf(stderr, "failed to register account\n");
			return 1;
		}

		/* we should write the user file again */
		if(add_account(&prof, &acc) != 0) {
			fprintf(stderr, "failed to add account to user file\n");
			return 1;
		}
	} else { /* login an existing account */
		if(login_account(&acc, &sc) != 0) {
			fprintf(stderr, "failed to login account\n");
			return 1;
		}

		/* load the friend file */
		if(read_friendfile(&acc) != 0) {
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

	/* we should spawn the manager thread here */

	return 0;
}

int handler_select() {
	int notiflen = notiflist_len(notifs);
	printf("%1d: message friend\n", 1);
	printf("%1d: view %d notification(s)\n", 2, notiflen);
	printf("%1d: add friend\n", 3);
	printf("%1d: exit\n", 0);

	uint64_t sel = num_prompt("selection", 0, 3);

	switch(sel) {
	case 0:
		stop = 1; break;
	case 1:
		if(select_conversation(&acc) != 0) {
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
	mode = v;
	release_writelock(&lock);
}

int get_mode() {
	acquire_readlock(&lock);
	int v = mode;
	release_readlock(&lock);
	return v;
}

