#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../util/defaults.h"

void usage(char *argv0) {
	fprintf(stderr, "usage: %s [-p port] [-d server_root_directory] <key file>\n", argv0);
}

int process_opts(int argc, char **argv, char **port, char **root_dir, char **keyfile);

int chat_server(int argc, char **argv) {
	char *port;
	char *root_dir;
	char *keyfile;

	if(process_opts(argc, argv, &port, &root_dir, &keyfile) != 0) {
		return 1;
	}

	printf("keyfile : %s\n"
	       "port    : %s\n"
	       "root_dir: %s\n", keyfile, port, root_dir);

	return 0;
}

int process_opts(int argc, char **argv, char **port, char **root_dir, char **keyfile) {
	*port = DFLT_PORT;
	*root_dir = DFLT_ROOT_DIR;

	char option;
	do {
		option = getopt(argc, argv, "p:d:");
		switch(option) {
		case 'p':
			*port = optarg;
			break;
		case 'd':
			*root_dir = optarg;
			break;
		}
	} while(option != -1);

	if(optind >= argc) {
		usage(argv[0]);
		return 1;
	}

	*keyfile = argv[optind];

	return 0;
}

