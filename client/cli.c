#include <stdio.h>

#include "account_file.h"
#include "login.h"
#include "connect_server.h"
#include "ibchat_client.h"

int init();
int main(int argc, char **argv) {
	/* initialize variables, etc. */
	if(init() != 0) {
		fprintf(stderr, "failed to initialize ibchat client\n");
		return 1;
	}

	struct account acc;

	/* log the user in */
	if(login_account(NULL, NULL, &acc)) {
		return 1;
	}
}

