#ifndef IBCHAT_CLIENT_IBCHAT_CLIENT_H
#define IBCHAT_CLIENT_IBCHAT_CLIENT_H

extern char *ROOT_DIR;

extern char *PORT;

extern int userfile_dirty;
extern int debug_mode;

char *file_path(uint8_t id[32]);

#endif

