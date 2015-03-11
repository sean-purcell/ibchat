#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../util/defaults.h"

void usage(char *argv0) {
	fprintf(stderr, "usage: %s [-p port] [-d server_root_directory] <key file>\n", argv0);
}

int chat_server(int argc, char **argv) {
	char *port = DFLT_PORT;
	char *root_dir = DFLT_ROOT_DIR;
	char *keyfile;

	char option;
	do {
		option = getopt(argc, argv, "p:d:");
		switch(option) {
		case 'p':
			port = optarg;
			break;
		case 'd':
			root_dir = optarg;
			break;
		}
	} while(option != -1);

	if(optind >= argc) {
		usage(argv[0]);
		return 1;
	}

	keyfile = argv[optind];

	printf("keyfile : %s\n"
	       "port    : %s\n"
	       "root_dir: %s\n", keyfile, port, root_dir);

	return 0;
}

