#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <wordexp.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <libibur/util.h>

#include "ibchat_client.h"

#include "../util/defaults.h"

char *ROOT_DIR = "~/.ibchat/";

/* this should be set to 1 by any function that modifies the userfile */
int userfile_dirty = 0;

static int expand_root_dir();
static int check_root_dir();
static int set_umask();
int init() {
	if(set_umask() != 0) return 1;
	if(expand_root_dir() != 0) return 1;
	if(check_root_dir() != 0) return 1;

	return 0;
}

/* expands the root directory into a full path */
static int expand_root_dir() {
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

		return 1;
	}

	strcpy(ROOT_DIR, expanded.we_wordv[0]);
	ROOT_DIR[strlen(expanded.we_wordv[0]) + 0] = '/';
	ROOT_DIR[strlen(expanded.we_wordv[0]) + 1] = '\0';

	wordfree(&expanded);

	return 0;
}

static int check_root_dir() {
	struct stat st = {0};
	if(stat(ROOT_DIR, &st) == -1) {
		if(errno != ENOENT) {
			perror("failed to open root directory");
			return -1;
		}

		/* directory doesn't exist, create it */
		printf("creating ibchat root directory\n");
		if(mkdir(ROOT_DIR, 0700) != 0) {
			perror("failed to create root directory");
			return -1;
		}
	} else {
		/* make sure its a directory */
		if(!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "specified root directory is not a directory: %s\n", ROOT_DIR);
			return -1;
		}
	}
	return 0;
}

static int set_umask() {
	umask(0077);
	return 0;
}

char *file_path(uint8_t id[32]) {
	size_t rootdir_len = strlen(ROOT_DIR);
	char *fname = malloc(rootdir_len + 64 + 1);
	if(fname == NULL) {
		fprintf(stderr, "failed to allocate memory for path\n");
		return NULL;
	}

	memcpy(fname, ROOT_DIR, rootdir_len);
	to_hex(id, 32, &fname[rootdir_len]);
	fname[rootdir_len + 64] = '\0';

	return fname;
}

