#include <stdio.h>
#include <stdlib.h>

#include "../util/defaults.h"

#include "login_server.h"
#include "line_prompt.h"
#include "account.h"
#include "connect_server.h"

int create_account(struct account *acc, struct server_connection *sc) {
start:;
	printf("server address [leave empty for default]: ");

	char *addr = line_prompt(NULL, NULL, 0);
	if(addr == NULL) {
		fprintf(stderr, "failed to read input\n");
		return -1;
	}

	if(strcmp(addr, "") == 0) {
		free(addr);
		addr = strdup(DFLT_ADDR);

		if(addr == NULL) {
			fprintf(stderr, "failed to duplicate string\n");
			return -1;
		}
	}

	/* we need to connect to the server to register */
	int ret = connect_server(addr, &(sc->ch), &(sc->server_key), &(sc->keys));
	if(ret != 0) {
		printf("try again? [y/n] ");
		char *resp = line_prompt(NULL, NULL, 0);
		if(resp == NULL) {
			fprintf(stderr, "failed to read input\n");
			return -1;
		}

		if((resp[0] | 32) != 'y') {
			return -1;
		}

		goto start;
	}

	return 0;
}

