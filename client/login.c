#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>

#include <ibcrypt/rand.h>
#include <ibcrypt/zfree.h>

#include "login.h"

int register_account(const char *uname, struct account *acc);
int user_exist(const char *uname);

/* the pointers can be left as null to prompt for them */
int login_account(char *uname, char *pass, struct account *acc) {
	int exist = user_exist();
	if(exist == -1) {
		perror("error reading user database");
		return -1;
	}
	if(exist == 0) {
		return register_account(uname, pass, acc);
	}

	int prmpt_un = 0;
	int prmpt_ps = 0;
	if(uname == NULL) {
		prmpt_un = 1;
		uname = line_prompt("username: ", NULL, 0);
		if(uname == NULL) {
			perror("Failed to read username");
			return -1;
		}
	}

	/* identify if the user exists first */
	int exist = user_exist(uname);
	if(exist == -1) {
		perror("Error reading user database");
		return -1;
	}
	if(exist == 0) {
		/* user does not exist, offer to register them */
		return register_account(uname, acc);
	}

	if(pass == NULL) {
		prmpt_ps = 1;
		pass = line_prompt("password: ", NULL, 1);
		if(pass == NULL) {
			perror("Failed to read password");
			return -1;
		}
	}

	return 10;
}

int register_account(const char *uname, struct account *acc) {
	printf("User not found.  Would you like to register a new user with the name %s? [y/n]", uname);
	fflush(stdout);

	char *ans = line_prompt(NULL, NULL, 0);

	if((ans[0] | 32) != 'y') {
		return 1;
	}

	char *pass = line_prompt("User password", "Confirm password", 1);

	printf("Registering %s\n", uname);
	printf("Pass: %s\n", pass);

	return 10;
}

int gen_login_data(struct login_data *data) {
	if(cs_rand(data->symm_seed, 32) != 0) {
		return 1;
	}
	if(cs_rand(data->hmac_seed, 32) != 0) {
		return 1;
	}
	if(rsa_gen_key(&data->id, 2048, 65537) != 0) {
		return 1;
	}

	return 0;
}

char* line_prompt(const char* prompt, const char* confprompt, int hide) {
	FILE* in;
	char *pw;
	char *confpw;
	struct termios term, term_old;
	int ttyin, ttyout;
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

	return 0;
}

