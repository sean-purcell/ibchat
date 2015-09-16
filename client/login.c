#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>

#include <ibcrypt/rand.h>
#include <ibcrypt/zfree.h>

#include <libibur/endian.h>

#include "login.h"
#include "userfile.h"

int register_account(const char *uname, const char *pass, struct account *acc);

/* the pointers can be left as null to prompt for them */
int login_account(char *uname, char *pass, struct account *acc) {
	int exist = user_exist();
	if(exist == -1) {
		perror("error finding user file");
		return -1;
	}
	if(exist == 0) {
		return register_account(uname, pass, acc);
	}

	int prmpt_ps = 0;

	if(pass == NULL) {
		prmpt_ps = 1;
		pass = line_prompt("password", NULL, 1);
		if(pass == NULL) {
			perror("failed to read password");
			return -1;
		}
	}

	printf("pass: %s\n", pass);

	return 10;
}

int register_account(const char *uname, const char *pass, struct account *acc) {
	printf("user file not found\ncreate new user? [y/n] ");
	fflush(stdout);

	char *ans = line_prompt(NULL, NULL, 0);

	if((ans[0] | 32) != 'y') {
		return 1;
	}

	int prmpt_un = 0;
	int prmpt_ps = 0;

	if(uname == NULL) {
		prmpt_un = 1;
		uname = line_prompt("username", NULL, 0);
		if(uname == NULL) {
			perror("failed to read username");
			return -1;
		}
	}

	if(pass == NULL) {
		prmpt_ps = 1;
		pass = line_prompt("password", "confirm password", 1);
		if(pass == NULL) {
			perror("failed to read password");
			return -1;
		}
	}

	printf("registering %s\n", uname);
	printf("pass: %s\n", pass);

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

	return 0;
}

/* returns the binary space required for this account */
uint64_t account_bin_size(struct account *acc) {
	uint64_t size = 0;
	size += 8;
	size += 8;
	size += 8;
	size += acc->u_len;
	size += acc->a_len;
	size += acc->k_len;

	return size;
}

/* returns the pointer at the end of the section written to
 * NULL if it failed */
uint8_t *account_write_bin(struct account *acc, uint8_t *ptr) {
	encbe64(acc->u_len, ptr); ptr += 8;
	encbe64(acc->a_len, ptr); ptr += 8;
	encbe64(acc->k_len, ptr); ptr += 8;
	memcpy(ptr, acc->uname, acc->u_len); ptr += acc->u_len;
	memcpy(ptr, acc->addr, acc->a_len); ptr += acc->a_len;
	memcpy(ptr, acc->key_bin, acc->k_len); ptr += acc->k_len;

	return ptr;
}

/* returns the pointer at the end of the section written to
 * NULL if it failed */
uint8_t *account_parse_bin(struct account **acc, uint8_t *ptr) {
	struct account *ap = malloc(sizeof(struct account));
	ap->u_len = decbe64(ptr); ptr += 8;
	ap->a_len = decbe64(ptr); ptr += 8;
	ap->k_len = decbe64(ptr); ptr += 8;

	ap->uname = malloc(ap->u_len + 1);
	if(ap->uname == NULL) {
		return NULL;
	}
	ap->addr = malloc(ap->a_len + 1);
	if(ap->addr == NULL) {
		return NULL;
	}
	ap->key_bin = malloc(ap->k_len + 1);
	if(ap->key_bin == NULL) {
		return NULL;
	}

	memcpy(ap->uname, ptr, ap->u_len);
	ptr += ap->u_len;
	ap->uname[ap->u_len] = '\0';

	memcpy(ap->addr, ptr, ap->a_len);
	ptr += ap->a_len;
	ap->addr[ap->a_len] = '\0';

	memcpy(ap->key_bin, ptr, ap->k_len);
	ptr += ap->k_len;

	*acc = ap;
	return ptr;
}

void account_free(struct account *acc) {
	zfree(acc->uname, acc->u_len);
	zfree(acc->addr, acc->a_len);
	zfree(acc->key_bin, acc->k_len);

	zfree(acc, sizeof(struct account));
}

void account_free_list(struct account *acc) {
	while(acc != NULL) {
		struct account *next = acc->next;
		account_free(acc);
		acc = next;
	}		
}

