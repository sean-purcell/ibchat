#ifndef CLIENT_CLI_H
#define CLIENT_CLI_H

#include "account.h"
#include "profile.h"
#include "login_server.h"
#include "notifications.h"

#include "../util/lock.h"

extern struct profile prof;
extern struct account acc;
extern struct server_connection sc;

extern struct notif *notifs;

extern struct lock lock;

extern int mode;
extern int stop;

void set_mode(int v);
/* NOTE: SHOULD ONLY BE CALLED IF LOCK IS ALREADY HELD */
void set_mode_no_lock(int v);
int get_mode();

#endif

