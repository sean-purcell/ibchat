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

#include "friends.h"
#include "cli.h"
#include "conversation.h"
#include "termctl.h"
#include "ibchat_client.h"

int select_conversation(struct account *acc) {
	start_conversation(NULL);
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
		fprintf(stderr, "error in selection\n");
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

int start_conversation(struct friend *f) {
	//int theight = termheight();
	/* load enough messages to fill the screen */
	struct cmessage *messages = cfile_load(f);

	set_ctl(1);
	clr_scrn();
	

	while(1) {
		char c;
		scanf("%c", &c);
		home_curs();
		printf("%x %d", c, isprint(c));
		repaint_conv(f, messages);
	}

	set_ctl(0);
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

	uint8_t buf[0x30];
	encbe64(0x30, &buf[0]);
	encbe64(0x00, &buf[8]);
	chacha_enc(f->f_symm_key, 32, 0, buf, buf, 16);
	hmac_sha256(f->f_hmac_key, 32, buf, 16, &buf[16]);

	if(fwrite(buf, 1, 0x30, file) != 0x30) {
		fprintf(stderr, "failed to write to conversation file: %s\n",
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

struct cmessage *cfile_load(struct friend *f) {
#define READ(buf, len) do {\
	if(fread(buf, 1, len, file) != len) {\
		fprintf(stderr, "conversation file read failed\n");\
		goto err;\
	}\
	} while(0)

#define MACCHK() do {\
	if(memcmp_ct(macf, macc, 0x20) != 0) {\
		fprintf(stderr, "conversation file invalid\n");\
		goto err;\
	}\
	} while(0)

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
		fprintf(stderr, "failed to open conversation file: %s\n",
			path);
		goto err;
	}

	HMAC_SHA256_CTX octx, hctx;
	hmac_sha256_init(&octx, f->f_hmac_key, 32);

	CHACHA_CTX cctx;

	uint8_t buf[0x30];
	uint8_t tmp[0x10];
	uint8_t macf[0x20];
	uint8_t macc[0x20];

	READ(buf, 0x30);

	hmac_sha256(f->f_hmac_key, 32, buf, 16, macc);
	memcpy(macf, &buf[16], 32);
	MACCHK();

	chacha_dec(f->f_symm_key, 32, 0, buf, buf, 16);
	uint64_t flen = decbe64(&buf[0]);
	uint64_t mnum = decbe64(&buf[8]);

	if(mnum != f->f_nonce) {
		fprintf(stderr, "conversation file invalid\n");
		goto err;
	}

	memcpy(buf, macf, 32);

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
			fprintf(stderr, "conversation file invalid\n");
			goto err;
		}

		/* the prefix is valid, load the message */
		*loc = alloc_cmessage(mlen);
		if(*loc == NULL) {
			fprintf(stderr, "failed to allocate memory\n");
			goto err;
		}

		READ((*loc)->text, mlen);

		{
			hctx = octx;
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

	if(pos != flen) {
		fprintf(stderr, "conversation file invalid\n");
		goto err;
	}

	goto end;
err:
	head = NULL;
end:
	free(path);
	if(file) fclose(file);
	release_readlock(&lock);
	memsets(&octx, 0, sizeof(HMAC_SHA256_CTX));
	memsets(&hctx, 0, sizeof(HMAC_SHA256_CTX));
	chacha_final(&cctx);

	memsets(tmp, 0, sizeof(tmp));

	return head;

#undef READ
}

struct cmessage *alloc_cmessage(uint64_t len) {
	struct cmessage *m = malloc(sizeof(struct cmessage));
	if(m == NULL) {
		return NULL;
	}
	m->text = malloc(len);
	if(m->text == NULL) {
		free(m);
		return NULL;
	}

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

