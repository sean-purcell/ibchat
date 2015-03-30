#ifndef IBCHAT_CLIENT_USERFILE_H
#define IBCHAT_CLIENT_USERFILE_H

#define UF_INV_UP     1
#define UF_INV_MAC    2
#define UF_OPEN_FAIL  3
#define UF_WRITE_FAIL 4
#define UF_READ_FAIL  5
#define UF_PROG_FAIL  6
#define UF_MEM_FAIL   7

int write_userfile(struct login_data *user, char *password, char *filename);
int read_userfile(struct user *user, char *password, char *filename);

#endif

