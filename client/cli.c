#include <stdio.h>

#include "account.h"
#include "login.h"
#include "connect_server.h"
#include "ibchat_client.h"
#include "login_server.h"

int init();
int main(int argc, char **argv) {
	/* initialize variables, etc. */
	if(init() != 0) {
		fprintf(stderr, "failed to initialize ibchat client\n");
		return 1;
	}

	int ret = 0;

	struct profile prof;
	struct account acc;
	struct server_connection sc;

	/* log the user in */
	if(login_profile(NULL, &prof) != 0) {
		printf("failed to login\n");
		return 1;
	}

	if((ret = pick_account(&prof, &acc)) < 0) {
		printf("failed to pick account\n");
		return 1;
	}

	if(ret == 0x55) { /* register a new account */
		if(create_account(&acc, &sc) != 0) {
			printf("failed to register account\n");
			return 1;
		}
	} else { /* login an existing account */
		
	}

	return 0;
}
