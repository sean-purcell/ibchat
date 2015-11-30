#include <stdio.h>

#include <libibur/util.h>

#include "bg_manager.h"
#include "login_server.h"
#include "cli.h"
#include "friendreq.h"

pthread_t bg_manager;

pthread_mutex_t bg_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t bg_wait  = PTHREAD_COND_INITIALIZER;

#define WAITTIME ((uint64_t) 100000ULL)

int add_umessage(struct message *m) {
	char buf[65536];
	to_hex(m->message, m->length, buf);
	printf("message received: %s\n", buf);
	return 0;
}

int add_pkeyresp(struct message *m) {
	pthread_mutex_lock(&bg_lock);
	if(get_mode() != 2) {
		pthread_mutex_unlock(&bg_lock);
		return -1;
	}

	pkey_resp = m;
	pthread_cond_broadcast(&bg_wait);
	pthread_mutex_unlock(&bg_lock);
	return 0;
}

int add_unotfound(struct message *m) {
	pthread_mutex_lock(&bg_lock);
	if(get_mode() != 2) {
		pthread_mutex_unlock(&bg_lock);
		return -1;
	}

	pkey_resp = m;
	pthread_cond_broadcast(&bg_wait);
	pthread_mutex_unlock(&bg_lock);
	return 0;
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

	fprintf(stderr, "background thread crashed\n");
	acquire_writelock(&lock);
	stop = 1;
	release_writelock(&lock);

	set_mode(-1);
	pthread_cond_broadcast(&bg_wait);

	return NULL;
}

int start_bg_thread(struct server_connection *sc) {
	if(pthread_create(&bg_manager, NULL, background_thread, sc) != 0) {
		fprintf(stderr, "failed to start background thread\n");
		return -1;
	}

	return 0;
}

