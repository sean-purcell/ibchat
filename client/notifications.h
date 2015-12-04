#ifndef CLIENT_NOTIFICATIONS_H
#define CLIENT_NOTIFICATIONS_H

#include <stdint.h>

#include "../util/lock.h"

#include "account.h"
#include "friends.h"
#include "friendreq.h"

struct notif {
	uint8_t type;

/* type = 1: message */
	struct friend *fr;
	uint64_t nunread;

/* type = 2: friend request */
	struct friendreq *freq;

/* type = 3: friend request response */
	/* use fr field above */

	/* linked list data */
	struct notif *next;
};

int notiflist_len(struct notif *n);

int init_notiffile(struct account *acc);
int write_notiffile(struct account *acc, struct notif *notifs);

uint64_t notif_bin_len(struct notif *n);
uint8_t *notif_bin_write(struct notif *n, uint8_t *ptr);
uint8_t *notif_bin_parse(struct account *acc, struct notif **n, uint8_t *ptr);

#endif

