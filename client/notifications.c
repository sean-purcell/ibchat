#include "cli.h"
#include "notifications.h"

int notiflist_len(struct notif *n) {
	acquire_readlock(&lock);
	int num = 0;
	struct notif *cur = n;
	while(cur) {
		num++;
		cur = cur->next;
	}

	release_readlock(&lock);

	return num;
}

