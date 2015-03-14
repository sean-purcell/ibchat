#ifndef IBCHAT_UTIL_USER_H
#define IBCHAT_UTIL_USER_H
#include <stdint.h>

/* the id of the user, defined as the sha256 hash of their username
 * terminated with '\0' */

/* for use in hash tables
 * the salt should be randomly chosen when the program starts */
uint64_t uid_hash(uint8_t salt[32], uint8_t uid[32]);

#endif

