#include <stdio.h>
#include <unistd.h>

#include "account.h"
#include "profile.h"
#include "connect_server.h"
#include "ibchat_client.h"
#include "login_server.h"
#include "friends.h"

struct profile prof;
struct account acc;
struct server_connection sc;

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

int handle_user() {
	return 0;
}

