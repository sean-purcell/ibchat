#include <stdio.h>
#include <wordexp.h>

#include "ibchat_client.h"

#include "../util/defaults.h"

char *ROOT_DIR = "~/.ibchat/";

char *PORT = DFLT_PORT;

static int expand_user_dir();
int init() {
	if(expand_user_dir() != 0) return 1;
}

/* expands the user directory into a full path */
static int expand_user_dir() {
	/* expand the root dir */
	wordexp_t expanded;
	if(wordexp(ROOT_DIR, &expanded, WRDE_UNDEF) != 0) {
		fprintf(stderr, "failed to expand root dir\n");
		return 1;
	}

	if(expanded.we_wordc != 1) {
		fprintf(stderr, "invalid root dir\n");
		return 1;
	}

	ROOT_DIR = malloc(strlen(expanded.we_wordv[0]) + 2);
	if(ROOT_DIR == NULL) {
		fprintf(stderr, "failed to allocate memory for root dir\n");	
	}

	strcpy(ROOT_DIR, expanded.we_wordv[0]);
	ROOT_DIR[strlen(expanded.we_wordv[0]) + 0] = '/';
	ROOT_DIR[strlen(expanded.we_wordv[0]) + 1] = '\0';

	wordfree(&expanded);
}

