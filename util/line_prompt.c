#include <termios.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <ibcrypt/zfree.h>

#include "line_prompt.h"

char* line_prompt(const char* prompt, const char* confprompt, int hide) {
	FILE* in;
	char *pw;
	char *confpw;
	struct termios term, term_old;
	int ttyin = 0, ttyout;
	size_t read;

	/* try to open the terminal */
	if(((in = fopen("/dev/tty", "r")) == NULL)) {
		in = stdin;
	}

	/* try to turn off echo */
	if(hide) {
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
	}
	ttyout = isatty(fileno(stdout));

tryagain:
	if(ttyout && prompt) {
		printf("%s: ", prompt);
		fflush(stdout);
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
				printf("passwords don't match, please try again\n");
			}
			zfree(pw, strlen(pw));
			zfree(confpw, strlen(confpw));
			goto tryagain;
		}
	}


	/* reset terminal */
	if(hide && ttyin) {
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

	return NULL;
}

uint64_t num_prompt(char *prompt, uint64_t min, uint64_t max) {
start:;
	int64_t res = 0;
	char *resp = line_prompt(prompt, NULL, 0);
	if(resp == NULL) {
		return ULLONG_MAX;
	}

	if(strlen(resp) > 18 || strlen(resp) < 1) {
		goto inv;
	}

	for(int i = 0; i < strlen(resp); i++) {
		int dig = resp[i] - '0';
		if(dig < 0 || dig > 9) {
			goto inv;
		}

		res = res * 10 + dig;
	}

	if(res < min || res > max) {
		goto inv;
	}

	return res;
inv:
	printf("invalid response, try again\n");
	goto start;
}

uint64_t num_prompt_no_retry(char *prompt, uint64_t min, uint64_t max) {
	int64_t res = 0;
	char *resp = line_prompt(prompt, NULL, 0);
	if(resp == NULL) {
		return ULLONG_MAX;
	}

	if(strlen(resp) > 18 || strlen(resp) < 1) {
		goto inv;
	}

	for(int i = 0; i < strlen(resp); i++) {
		int dig = resp[i] - '0';
		if(dig < 0 || dig > 9) {
			goto inv;
		}

		res = res * 10 + dig;
	}

	if(res < min || res > max) {
		goto inv;
	}

	return res;
inv:
	return ULLONG_MAX - 1;
}

int yn_prompt() {
	int ret = 0;
	char *ans = line_prompt(NULL, NULL, 0);
	if(ans == NULL) {
		perror("failed to read response");
		ret = -1;
		goto end;
	}

	if((ans[0] | 32) == 'y') {
		ret = 1;
		goto end;
	}

end:
	free(ans);
	return ret;
}

