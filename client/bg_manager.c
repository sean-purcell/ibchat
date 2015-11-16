#include <stdio.h>

#include "bg_manager.h"
#include "login_server.h"
#include "cli.h"

pthread_t bg_manager;

pthread_mutex_t bg_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t bg_wait  = PTHREAD_COND_INITIALIZER;

#define WAITTIME ((uint64_t) 1e5)

int add_umessage(struct message *m) {
	return -1;
}

int add_pkeyresp(struct message *m) {
	return -1;
}

int add_unotfound(struct message *m) {
	return -1;
}

void *background_thread(void *_arg) {
	struct server_connection *sc = (struct server_connection *) _arg;

	while(get_mode() != -1) {
		struct message *m = recv_message(sc->ch, &sc->keys, WAITTIME);
		if(m == NULL) continue;

		int ret = 0;
		switch(m->message[0]) {
		case 0:
			ret = add_umessage(m);
			break;
		case 1:
			ret = add_pkeyresp(m);
			break;
		case 0xff:
			ret = add_unotfound(m);
			break;
		}
		if(ret != 0) {
			break;
		}
	}

	fprintf(stderr, "background thread crashed, exiting\n");
	acquire_writelock(&lock);
	stop = 1;
	release_writelock(&lock);

	return NULL;
}

