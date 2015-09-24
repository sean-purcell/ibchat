#ifndef IBCHAT_CLIENT_LINE_PROMPT_H
#define IBCHAT_CLIENT_LINE_PROMPT_H

#include <stdint.h>

/* prompts an input line from the console */
char* line_prompt(const char* prompt, const char* confprompt, int hide);

/* returns ULLONG_MAX if error occurred */
uint64_t num_prompt(char *prompt, uint64_t min, uint64_t max);

#endif

