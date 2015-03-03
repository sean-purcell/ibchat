#ifndef IBCHAT_CRYPTO_KEYFILE_H
#define IBCHAT_CRYPTO_KEYFILE_H

#include <ibcrypt/rsa.h>

#define MEM_FAIL -1
#define CRYPTOGRAPHY_FAIL 1
#define OPEN_FAIL 2
#define WRITE_FAIL 3
#define READ_FAIL 4

int write_pri_key(RSA_KEY *key, const char *filename);
int write_pub_key(RSA_PUBLIC_KEY *pkey, const char *filename);

int read_pri_key(const char *filename, RSA_KEY *key);
int read_pub_key(const char *filename, RSA_PUBLIC_KEY *pkey);

#endif

