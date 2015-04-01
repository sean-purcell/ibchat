#ifndef IBCHAT_CLIENT_USERFILE_H
#define IBCHAT_CLIENT_USERFILE_H

#include "login.h"

#define UF_INV_PASS    1
#define UF_INV_MAC     2
#define UF_OPEN_FAIL   3
#define UF_WRITE_FAIL  4
#define UF_READ_FAIL   5
#define UF_PROG_FAIL   6
#define UF_MEM_FAIL    7
#define UF_CLOSE_FAIL  8
#define UF_INV_MAGIC   9
#define UF_INV_UID    10

int write_userfile(struct login_data *user, char *filename);
int read_userfile(struct login_data *user, char *filename);

#endif

