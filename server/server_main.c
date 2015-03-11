#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int gen_key(int, char**);
int help(int, char**);

struct program {
	int (*main)(int, char**);
	char *name;
};

struct program programs[] = {
	{ &gen_key, "keygen" },
	{ &help, "help" },
};

int help(int argc, char **argv) {
	fprintf(stderr, "available programs:\n");
	int i;
	for(i = 0; i < sizeof(programs)/sizeof(programs[0]); i++) {
		fprintf(stderr, "%s\n", programs[i].name);
	}
	return 0;
}

int main(int argc, char **argv) {
	if(argc == 1) {
		fprintf(stderr, "usage: %s <program name>\n", argv[0]);
		return 1;
	}

	int (*cmd)(int, char **) = NULL;
	int i;

	for(i = 0; i < sizeof(programs)/sizeof(programs[0]); i++) {
		if(strcmp(argv[1], programs[i].name) == 0) {
			cmd = programs[i].main;
			break;
		}
	}

	if(cmd == NULL) {
		fprintf(stderr, "program %s not found\n", argv[1]);
		help(argc, argv);
		return 1;
	}

	return cmd(argc, argv);
}

