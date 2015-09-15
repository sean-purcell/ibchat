#ifndef IBCHAT_UTIL_USER_H
#define IBCHAT_UTIL_USER_H
#include <stdint.h>

struct user {

};

char *getusername(const char *prompt, FILE *out);

/* usernames must match /[a-zA-Z0-9_]+/ */

int valid_uname(char *uname, size_t ulen);

/* the id of the user, defined as the sha256 hash of their username
 * terminated with '\0' */
void gen_uid(char *uname, size_t ulen, uint8_t uid[32]);

/* for use in hash tables
 * the salt should be randomly chosen when the program starts */
void uid_hash(uint8_t salt[32], uint8_t uid[32], uint8_t hash[32]);
uint64_t uid_hash_val(uint8_t salt[32], uint8_t uid[32]);

#endif

