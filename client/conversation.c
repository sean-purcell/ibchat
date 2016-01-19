#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <ctype.h>

#include <sys/ioctl.h>

#include <ibcrypt/chacha.h>
#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "../util/line_prompt.h"
#include "../util/log.h"

#include "friends.h"
#include "cli.h"
#include "conversation.h"
#include "termctl.h"
#include "ibchat_client.h"
#include "uname.h"
#include "bg_manager.h"

int select_conversation(struct account *acc) {
	/* list friends so one can be selected */
	acquire_readlock(&lock);
	int fnum = 0;
	struct friend *f = acc->friends;
	while(f) {
		printf("%4d: %s\n", fnum+1, f->uname);
		fnum++;
		f = f->next;
	}

	if(fnum == 0) {
		printf("you have no friends\n");
		return 0;
	}

	printf("%4d: go back\n", 0);

	int sel = num_prompt("selection", 0, fnum);

	if(sel == 0) {
		return 0;
	}
	if(sel > fnum) {
		ERR("error in selection");
		return 1;
	}

	f = acc->friends;
	while(sel > 1) {
		f = f->next;
		sel--;
	}
	release_readlock(&lock);

	return start_conversation(f);
}

void repaint_conv(struct friend *f, struct cmessage *head) {
	
}

int start_conversation_graphic(struct friend *f) {
	cur_conv = f;
	new_messages = NULL;
	set_mode(1);
	//int theight = termheight();
	/* load enough messages to fill the screen */
	struct cmessage *messages = NULL;
	if(cfile_load(f, &messages) != 0) {
		return -1;
	}

	set_ctl(1);
	clr_scrn();

	while(1) {
		char c;
		if(scanf("%c", &c) != 1) continue;
		home_curs();
		printf("%x %d", c, isprint(c));
		repaint_conv(f, messages);
	}

	set_ctl(0);
	set_mode(0);
	cur_conv = NULL;
	new_messages = NULL;
}

static int cmessage_send_server(struct friend *f, struct cmessage *m) {
	int ret = -1;

	uint64_t mlen = strlen(m->text);
	uint64_t tlen = 0x29 + 0x11 + mlen + 0x20;

	uint8_t *buf = malloc(tlen);
	if(buf == NULL) {
		ERR("failed to allocate memory");
		tlen = 0;
		goto err;
	}

	/* handle the nonce increment */
	f->s_nonce += 1;
	if(f->s_nonce == 0) {
		ERR("too many messages with one friend");
		goto err;
	}

	/* prepare message */
	uint8_t *ptr = buf;
	*ptr = 0; ptr++;
	gen_uid(f->uname, ptr); ptr += 0x20;
	encbe64(tlen - 0x29, ptr); ptr += 8;

	*ptr = 0; ptr++;

	encbe64(f->s_nonce, ptr); ptr += 8;

	encbe64(mlen, ptr); ptr += 8;

	chacha_enc(f->s_symm_key, 32, f->s_nonce, (uint8_t*)m->text, ptr, mlen);
	ptr += mlen;

	hmac_sha256(f->s_hmac_key, 32, &buf[0x29], tlen - 0x49, ptr);
	ptr += 0x20;

	if(ptr - buf != tlen) {
		ERR("invalid message length");
	}

	if(acquire_netlock() != 0) {
		goto err;
	}

	if(send_message(sc.ch, &sc.keys, buf, tlen) != 0) {
		ERR("failed to send message");
		release_netlock();
		goto err;
	}

	release_netlock();

	ret = 0;
err:
	zfree(buf, tlen);

	return ret;
}

static int cmessage_send(struct friend *f, char *text, struct cmessage **head) {
	int ret = -1;

	uint64_t len = strlen(text);

	struct cmessage *m = alloc_cmessage(len);
	m->sender = 0;
	strcpy(m->text, text);

	m->next = NULL;
	m->prev = NULL;

	if(cmessage_send_server(f, m) != 0) {
		goto err;
	}
	if(cfile_add(f, m) != 0) {
		goto err;
	}

	m->prev = *head;
	if(*head) {
		(*head)->next = m;
	}
	*head = m;

	ret = 0;
err:
	if(ret) free_cmessage(m);

	return ret;
}

int start_conversation(struct friend *f) {
#define PRINT_MESSAGE(__mess) do {\
	char *sender;\
	if(__mess->sender == 0) {\
		sender = acc->uname;\
	} else {\
		sender = f->uname;\
	}\
	printf("%s: %s\n", sender, __mess->text);\
} while(0)

	int ret = -1;

	acquire_writelock(&lock);
	cur_conv = f;
	new_messages = NULL;
	set_mode_no_lock(1);
	release_writelock(&lock);

	struct cmessage *messages = NULL;
	struct cmessage *head = NULL;

	if(cfile_check(f) != 0) {
		ERR("failed to initialize conversation file");
		goto err;
	}
	if(cfile_load(f, &messages) != 0) {
		ERR("failed to load conversation file");
		goto err;
	}

	/* print out all previous messages */
	{
		struct cmessage *cur = messages;
		while(cur != NULL) {
			PRINT_MESSAGE(cur);
			head = cur;
			cur = cur->next;
		}
	}

	while(1) {
		/* conversation loop */
		fd_set fds;
		{
			/* wait for stdin */
			FD_SET(STDIN_FILENO, &fds);
			struct timeval wait;
			wait.tv_sec = 0;
			wait.tv_usec = 500000L;

			select(STDIN_FILENO + 1, &fds, NULL, NULL, &wait);
		}
		if(FD_ISSET(STDIN_FILENO, &fds)) {
			/* get new message and process it */
			char *text = line_prompt(NULL, NULL, 0);
			if(text == NULL) {
				goto err;
			}

			if(text[0] == '\0') {
				/* empty message, ignore */
			} else if(text[0] == '/') {
				/* command, process */
				if(strcmp(text, "/exit") == 0) {
					goto end;
				} else {
					printf("unrecognized command\n");
				}
			} else {
				/* new message */
				if(cmessage_send(f, text, &head) != 0) {
					goto err;
				}
				/* overwrite the display'ed version */
				printf("\033[1A");
				PRINT_MESSAGE(head);
			}
		}

		acquire_writelock(&lock);
		if(new_messages != NULL) {
			/* new messages are from most recent to most distant */
			struct cmessage *cur = new_messages;
			while(cur->next != NULL) {
				cur = cur->next;
			}
			/* now read them in reverse */
			while(cur != NULL) {
				printf("\033[1G\n\033[1A");
				PRINT_MESSAGE(cur);
				printf("\033[1B");
				struct cmessage *next = cur->prev;
				cur->prev = head;
				cur->next = NULL;
				head->next = cur;
				head = cur;
				cur = next;
			}
			new_messages = NULL;
		}
		release_writelock(&lock);
	}

end:;
	ret = 0;
err:;
	free_cmessage_list(messages);
	set_mode(0);
	return ret;
}

static int parse_conv_message_payload(struct friend *f,
	uint8_t *payload, uint64_t plen,
	struct cmessage **m);

int parse_conv_message(uint8_t *sender, uint8_t *payload, uint64_t plen) {
	int ret = -1;

	struct friend *f = NULL;
	struct cmessage *m = NULL;

	/* first see if we have a friend with the given id */
	f = acc->friends;
	while(f) {
		if(memcmp(f->uid, sender, 32) == 0) {
			break;
		}
		f = f->next;
	}
	if(f == NULL) {
		LOG("message sender unidentified");
		/* not found, invalid message */
		goto inv;
	}

	int res = parse_conv_message_payload(f, payload, plen, &m);
	if(res < 0) {
		ERR("failed to parse message");
		goto err;
	} else if(res > 0) {
		ERR("invalid message, discarded");
		goto inv;
	}

	/* add it to the conversation file */
	if(cfile_add(f, m) != 0) {
		ERR("failed to add to conversation file");
		goto err;
	}

	/* if we're in conversation add to current conversation */
	acquire_readlock(&lock);
	if(get_mode_no_lock() == 1) {
		if(cur_conv == f) {
			m->next = new_messages;
			if(new_messages) new_messages->prev = m;
			new_messages = m;
		}
	}
	release_readlock(&lock);

	/* everything is valid, message is parsed, place it in the queue */
	if(add_new_message(f) != 0) {
		goto err;
	}

inv:
	ret = 0;
err:
	return ret;
}

static int parse_conv_message_payload(struct friend *f,
	uint8_t *payload, uint64_t plen,
	struct cmessage **_m) {

	int ret = -1, inv = -1;

	uint8_t macc[0x20], *macf;

	uint64_t mlen, nonce;

	struct cmessage *m = NULL;

	if(plen < 0x11) {
		LOG("invalid message length");
		goto inv;
	}

	mlen = decbe64(&payload[0x9]);
	if(plen != 0x11 + mlen + 0x20) {
		LOG("invalid message length field");
		goto inv;
	}

	nonce = decbe64(&payload[0x1]);
	if(nonce <= f->r_nonce) {
		LOG("invalid nonce");
		goto inv;
	}
	f->r_nonce = nonce;

	macf = &payload[plen - 0x20];
	hmac_sha256(f->r_hmac_key, 32, payload, plen - 32, macc);

	if(memcmp_ct(macf, macc, 0x20) != 0) {
		LOG("invalid message authentication");
		goto inv;
	}

	m = alloc_cmessage(mlen);
	if(m == NULL) {
		ERR("failed to allocate memory");
		goto err;
	}

	m->sender = 1;
	chacha_dec(f->r_symm_key, 32, f->r_nonce, &payload[0x11],
		(uint8_t *) m->text, mlen);

	m->next = NULL;
	m->prev = NULL;

	/* we're done */
	*_m = m;

	inv = 0;
inv:
	ret = 0;
err:
	/* cleanup */
	memsets(macc, 0, sizeof(macc));
	if((ret || inv) && m) free_cmessage(m);

	return ret ? -1 : (inv ? 1 : 0);
}

/* defines the first set of 32 bytes used for the MAC of the first message */
static uint8_t INITIAL_PREV_MAC[32] = {
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
};

int cfile_check(struct friend *f) {
	FILE *file = NULL;
	char *path = NULL;

	path = file_path(f->c_file);
	if(path == NULL) {
		goto err;
	}
	file = fopen(path, "rb");

	int exists = file != NULL;

	fclose(file);
	free(path);

	return exists ? 0 : cfile_init(f);

err:
	return -1;
}

int cfile_init(struct friend *f) {
	acquire_writelock(&lock);
	int ret = 0;

	char *path = NULL;
	FILE *file = NULL;

	path = file_path(f->c_file);
	if(path == NULL) {
		goto err;
	}
	file = fopen(path, "wb");
	if(file == NULL) {
		goto err;
	}

	uint8_t buf[0x30];
	encbe64(0x30, &buf[0]);
	encbe64(0x00, &buf[8]);
	hmac_sha256(f->f_hmac_key, 32, buf, 16, &buf[16]);

	if(fwrite(buf, 1, 0x30, file) != 0x30) {
		ERR("failed to write to conversation file: %s",
			path);
		goto err;
	}

	goto end;
err:
	ret = -1;
end:
	if(path) free(path);
	if(file) fclose(file);

	release_writelock(&lock);
	return ret;
}

int cfile_load(struct friend *f, struct cmessage **messages) {
#define READ(buf, len) do {\
	if(fread(buf, 1, len, file) != len) {\
		ERR("conversation file read failed");\
		goto err;\
	}\
	} while(0)

#define MACCHK() do {\
	if(memcmp_ct(macf, macc, 0x20) != 0) {\
		ERR("conversation file invalid");\
		goto err;\
	}\
	} while(0)

	int ret = 0;

	acquire_readlock(&lock);

	struct cmessage *head = NULL, *prev = NULL;
	struct cmessage **loc = &head;

	FILE *file = NULL;

	char *path = file_path(f->c_file);
	if(path == NULL) {
		goto err;
	}

	file = fopen(path, "rb");
	if(file == NULL) {
		ERR("failed to open conversation file: %s",
			path);
		goto err;
	}

	HMAC_SHA256_CTX hctx;

	CHACHA_CTX cctx;

	uint8_t buf[0x30];
	uint8_t tmp[0x10];
	uint8_t macf[0x20];
	uint8_t macc[0x20];

	READ(buf, 0x30);

	hmac_sha256(f->f_hmac_key, 32, buf, 16, macc);
	memcpy(macf, &buf[16], 32);
	MACCHK();

	uint64_t flen = decbe64(&buf[0]);
	uint64_t mnum = decbe64(&buf[8]);

	memcpy(buf, INITIAL_PREV_MAC, 32);

	uint64_t pos = 0x30;
	uint64_t i;
	for(i = 1; i <= mnum; i++) {
		chacha_init(&cctx, f->f_symm_key, 32, i);
		READ(&buf[0x20], 0x10);
		READ(macf, 0x20);

		hmac_sha256(f->f_hmac_key, 32, buf, 0x30, macc);
		MACCHK();

		chacha_stream(&cctx, &buf[0x20], tmp, 16);

		uint64_t mlen = decbe64(&tmp[0]);
		uint64_t sender = decbe64(&tmp[8]);
		if(sender != 0 && sender != 1) {
			ERR("conversation file invalid");
			goto err;
		}

		/* the prefix is valid, load the message */
		*loc = alloc_cmessage(mlen);
		if(*loc == NULL) {
			ERR("failed to allocate memory");
			goto err;
		}

		READ((*loc)->text, mlen);
		(*loc)->sender = sender;

		{
			hmac_sha256_init(&hctx, f->f_hmac_key, 32);
			hmac_sha256_update(&hctx, &buf[0x20], 16);
			hmac_sha256_update(&hctx, macf, 0x20);
			hmac_sha256_update(&hctx, (uint8_t*)(*loc)->text, mlen);
			hmac_sha256_final(&hctx, macc);
		}
		READ(macf, 0x20);

		MACCHK();

		/* message is clean, decrypt it */
		chacha_stream(&cctx, (uint8_t*)(*loc)->text,
			(uint8_t*)(*loc)->text, mlen);

		/* move the mac into the buffer for the next iteration */
		memcpy(buf, macf, 0x20);

		/* move pointers around */
		if(prev) {
			prev->next = *loc;
		}
		(*loc)->prev = prev;
		prev = *loc;
		loc = &(*loc)->next;

		/* update the length field */
		pos += 0x30 + 0x20 + mlen;

		chacha_final(&cctx);
	}

	/* nullify the final next field */
	*loc = NULL;

	if(pos != flen) {
		ERR("conversation file invalid");
		goto err;
	}

	goto end;
err:
	head = NULL;
	ret = -1;
end:
	free(path);
	if(file) fclose(file);
	memsets(&hctx, 0, sizeof(HMAC_SHA256_CTX));
	chacha_final(&cctx);

	memsets(tmp, 0, sizeof(tmp));

	release_readlock(&lock);
	*messages = head;
	return ret;

#undef READ
#undef MACCHK
}

int cfile_add(struct friend *f, struct cmessage *m) {
#define READ(buf, len) do {\
	if(fread(buf, 1, len, file) != len) {\
		ERR("conversation file read failed");\
		goto err;\
	}\
	} while(0)

#define WRITE(buf, len) do {\
	if(fwrite(buf, 1, len, file) != len) {\
		ERR("conversation file write failed");\
		goto err;\
	}\
	} while(0)

#define SEEK(pos) do {\
	if(fseek(file, pos, SEEK_SET) != 0) {\
		ERR("failed to seek conversation file");\
		goto err;\
	}\
	} while(0)

#define MACCHK() do {\
	if(memcmp_ct(macf, macc, 0x20) != 0) {\
		ERR("conversation file invalid");\
		goto err;\
	}\
	} while(0)

	if(cfile_check(f) != 0) return -1;

	int ret = 0;

	acquire_writelock(&lock);

	uint8_t *encm = NULL;
	FILE *file = NULL;

	char *path = file_path(f->c_file);
	if(path == NULL) {
		goto err;
	}

	file = fopen(path, "rb+");
	if(file == NULL) {
		ERR("failed to open conversation file: %s",
			path);
		goto err;
	}

	HMAC_SHA256_CTX hctx;
	hmac_sha256_init(&hctx, f->f_hmac_key, 32);

	CHACHA_CTX cctx;

	uint8_t buf[0x30];
	uint8_t macf[0x20];
	uint8_t macc[0x20];

	READ(buf, 0x30);

	hmac_sha256(f->f_hmac_key, 32, buf, 16, macc);
	memcpy(macf, &buf[16], 32);
	MACCHK();

	uint64_t flen = decbe64(&buf[0]);
	uint64_t mnum = decbe64(&buf[8]);

	uint64_t mlen = strlen(m->text);

	/* write the new values in before we jump to the end */
	encbe64(flen + 0x50 + mlen, &buf[0]);
	encbe64(mnum + 1, &buf[8]);

	hmac_sha256(f->f_hmac_key, 32, buf, 16, &buf[16]);
	SEEK(0);

	WRITE(buf, 0x30);

	SEEK(flen - 32);

	READ(buf, 0x20);
	fflush(file);
	if(mnum == 0) { /* this is the first message, use a different MAC */
		memcpy(buf, INITIAL_PREV_MAC, 0x20);
	}
	encbe64(mlen, &buf[32]);
	encbe64(m->sender, &buf[40]);

	chacha_init(&cctx, f->f_symm_key, 32, mnum + 1);
	chacha_stream(&cctx, &buf[32], &buf[32], 16);

	hmac_sha256(f->f_hmac_key, 32, buf, 0x30, macc);

	WRITE(&buf[0x20], 0x10);
	WRITE(macc, 0x20);

	encm = malloc(mlen);
	if(encm == NULL) {
		ERR("failed to allocate memory");
		goto err;
	}

	chacha_stream(&cctx, (uint8_t*)m->text, encm, mlen);
	WRITE(encm, mlen);

	hmac_sha256_init(&hctx, f->f_hmac_key, 32);
	hmac_sha256_update(&hctx, &buf[0x20], 16);
	hmac_sha256_update(&hctx, macc, 32);
	hmac_sha256_update(&hctx, encm, mlen);
	hmac_sha256_final(&hctx, macc);

	WRITE(macc, 32);

	goto end;
err:
	ret = -1;
end:
	free(path);
	if(file) fclose(file);
	free(encm);
	memsets(&hctx, 0, sizeof(HMAC_SHA256_CTX));
	chacha_final(&cctx);

	release_writelock(&lock);
	return ret;

#undef READ
#undef WRITE
#undef MACCHK
}

struct cmessage *alloc_cmessage(uint64_t len) {
	struct cmessage *m = malloc(sizeof(struct cmessage));
	if(m == NULL) {
		return NULL;
	}
	m->text = malloc(len + 1);
	if(m->text == NULL) {
		free(m);
		return NULL;
	}
	m->text[len] = 0;

	return m;
}

void free_cmessage(struct cmessage *m) {
	zfree(m->text, strlen(m->text));
	free(m);
}

void free_cmessage_list(struct cmessage *m) {
	while(m) {
		struct cmessage *next = m->next;
		free_cmessage(m);
		m = next;
	}
}

