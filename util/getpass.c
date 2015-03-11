#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "getpass.h"

char* ibchat_getpass(const char* prompt, const char* confprompt, int usetty) {
	FILE* in;
	char *pw;
	char *confpw;
	struct termios term, term_old;
	int ttyin, ttyout;
	size_t read;

	/* try to open the terminal */
	if(!usetty || ((in = fopen("/dev/tty", "r")) == NULL)) {
		in = stdin;
	}

	/* try to turn off echo */
	if((ttyin = isatty(fileno(in))) != 0) {
		if(tcgetattr(fileno(in), &term_old)) {
			/* failed */
			goto err0;
		}
		memcpy(&term, &term_old, sizeof(struct termios));
		term.c_lflag = (term.c_lflag & ~ECHO) | ECHONL;
		if(tcsetattr(fileno(in), TCSANOW, &term)) {
			goto err0;
		}
	}
	ttyout = isatty(fileno(stdout));

tryagain:
	if(ttyout) {
		printf("%s: ", prompt);
	}

	pw = 0;
	confpw = 0;

	read = 0;
	if((read = getline(&pw, &read, in)) == -1) {
		zfree(pw, strlen(pw));
		goto err0;
	}
	/* remove the new line */
	pw[read-1] = '\0';

	if(confprompt != NULL) {
		if(ttyout) {
			printf("%s: ", confprompt);
		}
		
		read = 0;
		if((read = getline(&confpw, &read, in)) == -1) {
			goto err1;
		}
		confpw[read-1] = '\0';

		if(strcmp(pw, confpw) != 0) {
			if(ttyout) {
				printf("Passwords don't match, please try again\n");
			}
			zfree(pw, strlen(pw));
			zfree(confpw, strlen(confpw));
			goto tryagain;
		}
	}


	/* reset terminal */
	if(ttyin) {
		if(tcsetattr(fileno(in), TCSANOW, &term_old)) {
			goto err1;
		}
		fclose(in);
	}

	if(confprompt != NULL) {
		zfree(confpw, strlen(confpw));
	}

	return pw;

err1:
	zfree(pw, strlen(pw));
	if(confprompt != NULL) {
		zfree(confpw, strlen(confpw));
	}
err0:
	if(ttyin) {
		fclose(in);
	}

	return 0;
}

