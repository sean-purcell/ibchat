#ifndef IBCHAT_CRYPTO_KEYFILE_H
#define IBCHAT_CRYPTO_KEYFILE_H

#include <ibcrypt/rsa.h>

#define MEM_FAIL -1
#define CRYPTOGRAPHY_FAIL 1
#define OPEN_FAIL 2
#define WRITE_FAIL 3
#define READ_FAIL 4
#define INVALID_FILE 5
#define INVALID_MAC 6
#define NO_PASSWORD 7

/* if password is NULL it will be encrypted without a key */
int write_pri_key(RSA_KEY *key, const char *filename, char *password);
int write_pub_key(RSA_PUBLIC_KEY *pkey, const char *filename);

/* if password is NULL and needed, it will cause an error */
int read_pri_key(const char *filename, RSA_KEY *key, char *password);
int read_pub_key(const char *filename, RSA_PUBLIC_KEY *pkey);

#endif

