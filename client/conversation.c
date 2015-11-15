#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <ctype.h>

#include <sys/ioctl.h>

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
	return -1;
}

struct cmessage *cfile_load(struct friend *f) {
	return NULL;
	/*
	acquire_readlock(&lock);

	struct cmessage *head = NULL;
	struct cmessage **loc = &head;

	char *path = file_path(f->c_file);
	if(path == NULL) {
		goto err;
	}

	FILE *file = fopen(path, "rb");
	if(file == NULL) {
		fprintf(stderr, "failed to open conversation file: %s\n",
			path);
		goto err;
	}

	uint8_t a;

	goto end;
err:
	head = NULL;
end:
	free(path);
	if(file) fclose(file);
	release_readlock(&lock);

	return head;
	*/
}

