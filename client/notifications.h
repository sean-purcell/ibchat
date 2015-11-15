#ifndef CLIENT_NOTIFICATIONS_H
#define CLIENT_NOTIFICATIONS_H

#include "../util/lock.h"

struct notif {
	int type;

/* type = 1: message */
	struct friend *fr;
	int nunread;

/* type = 2: friend request */
	struct friendreq *freq;

/* type = 3: friend request response */
	/* use fr field above */

	/* linked list data */
	struct notif *next;
};

int notiflist_len(struct notif *n);

#endif

