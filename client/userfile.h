#ifndef IBCHAT_CLIENT_USERFILE_H
#define IBCHAT_CLIENT_USERFILE_H

#include "profile.h"

int write_userfile(struct profile *user);
int read_userfile(struct profile *user);

int user_exist();

#endif

