#include <stdio.h>

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

	struct profile prof;

	/* log the user in */
	if(login_profile(NULL, &prof)) {
		return 1;
	}
}

