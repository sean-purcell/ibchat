#ifndef IBCHAT_SERVER_CHAT_SERVER_H
#define IBCHAT_SERVER_CHAT_SERVER_H

#include <ibcrypt/rsa.h>

/* private info */
extern RSA_KEY server_key;
extern char *password;
/* ---------------------- */

extern RSA_PUBLIC_KEY server_pub_key;

#endif

