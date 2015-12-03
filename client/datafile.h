#ifndef CLIENT_DATAFILE_H
#define CLIENT_DATAFILE_H

struct format_desc {
	uint64_t pref_len;
	int (*p_fill)(void *arg, uint8_t *ptr);
	int (*s_key)(void *arg, uint8_t *ptr, uint8_t *key);
	int (*h_key)(void *arg, uint8_t *ptr, uint8_t *key);

	size_t next_off;
	uint64_t (*datalen)(void *data);
	uint8_t *(*datawrite)(void *data, uint8_t *ptr);
	uint8_t *(*dataread)(void **data, uint8_t *ptr);
};

int write_datafile(char *path, void *arg, void *data, struct format_desc *f);

#endif

