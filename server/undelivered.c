#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <sys/stat.h>

#include <ibcrypt/sha256.h>
#include <ibcrypt/zfree.h>

#include <libibur/util.h>
#include <libibur/endian.h>

#include "../util/log.h"

#include "undelivered.h"
#include "user_db.h"

/* defines the first set of 32 bytes used for the MAC of the first message */
static uint8_t INITIAL_PREV_MAC[32] = {
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
};

static const char *UNDEL_DIR_SUFFIX = "/undel/";

static char *UNDEL_DIR;

int check_undel_dir() {
	struct stat st = {0};
	if(stat(UNDEL_DIR, &st) == -1) {
		if(errno != ENOENT) {
			ERR("failed to open undel directory: %s", UNDEL_DIR);
			return -1;
		}

		/* directory doesn't exist, create it */
		if(mkdir(UNDEL_DIR, 0700) != 0) {
			ERR("failed to create undel directory: %s", UNDEL_DIR);
			return -1;
		}
	} else {
		/* make sure its a directory */
		if(!S_ISDIR(st.st_mode)) {
			ERR("specified undel directory is not a directory: %s",
				UNDEL_DIR);
			return -1;
		}
	}
	return 0;
}

static char *undel_path(struct user *u) {
	char *path = malloc(strlen(UNDEL_DIR) + 64 + 1);
	if(path == NULL) return NULL;
	strcpy(path, UNDEL_DIR);
	to_hex(u->uid, 32, &path[strlen(UNDEL_DIR)]);

	return path;
}

int undel_init_file(struct user *u) {
	char *path = undel_path(u);
	if(path == NULL) {
		ERR("failed to allocate memory");
		return -1;
	}

	FILE *f = fopen(path, "wb");
	if(f == NULL) {
		ERR("failed to open undel file: %s", path);
		free(path);
		return -1;
	}

	uint8_t buf[0x30];
	encbe64(0x30, &buf[0]);
	encbe64(0x00, &buf[8]);
	hmac_sha256(u->und_auth, 32, buf, 0x10, &buf[0x10]);

	int ret = 0;

	if(fwrite(buf, 1, 0x30, f) != 0x30) {
		ERR("failed to write to undel file: %s", path);
		ret = -1;
	}

	free(path);
	fclose(f);

	return ret;
}

int undel_add_message(struct user *u, uint8_t *message, uint64_t len) {
#define READ(buf, size) do {\
	if(fread(buf, size, 1, f) != 1) {\
		ERR("failed to read from file: %s", path);\
		goto err;\
	}\
} while(0)

#define WRITE(buf, size) do {\
	if(fwrite(buf, size, 1, f) != 1) {\
		ERR("failed to write to file: %s", path);\
		goto err;\
	}\
} while(0)

#define SEEK(pos) do {\
	if(fseek(f, pos, SEEK_SET) != 0) {\
		ERR("failed to seek undelivered file");\
		goto err;\
	}\
} while(0)

#define MACCHK() do {\
	if(memcmp_ct(macc, macf, 0x20) != 0) {\
		ERR("invalid mac in %s", path);\
		goto err;\
	}\
} while(0)

	int ret = -1;

	char *path = undel_path(u);
	if(path == NULL) {
		ERR("failed to allocate memory");
		return -1;
	}
	FILE *f = fopen(path, "rb+");
	if(f == NULL) {
		ERR("failed to open file: %s", path);
		goto err;
	}

	uint8_t macc[0x20], *macf;
	uint8_t prefix[0x30];
	uint8_t prev_mac[0x20];
	uint8_t len_buf[8];

	HMAC_SHA256_CTX hctx;

	READ(prefix, 0x30);

	hmac_sha256(u->und_auth, 32, prefix, 0x10, macc);
	macf = &prefix[0x10];

	MACCHK();

	uint64_t flen = decbe64(&prefix[0]);
	uint64_t mnum = decbe64(&prefix[8]);

	/* write in new values */
	SEEK(0);

	encbe64(flen + 8 + len + 32, &prefix[0]);
	encbe64(mnum + 1, &prefix[8]);
	hmac_sha256(u->und_auth, 32, prefix, 0x10, &prefix[0x10]);

	WRITE(prefix, 0x30);

	SEEK(flen - 32);

	READ(prev_mac, 0x20);
	if(mnum == 0) { /* first message */
		memcpy(prev_mac, INITIAL_PREV_MAC, 0x20);
	}

	encbe64(len, len_buf);

	hmac_sha256_init(&hctx, u->und_auth, 32);
	hmac_sha256_update(&hctx, prev_mac, 32);
	hmac_sha256_update(&hctx, len_buf, 8);
	hmac_sha256_update(&hctx, message, len);
	hmac_sha256_final(&hctx, prev_mac);

	fflush(f);
	WRITE(len_buf, 8);
	WRITE(message, len);
	WRITE(prev_mac, 0x20);

	ret = 0;
err:
	free(path);
	memsets(macc, 0, sizeof(macc));
	memsets(prefix, 0, sizeof(prefix));
	memsets(prev_mac, 0, sizeof(prev_mac));
	memsets(len_buf, 0, sizeof(len_buf));
	memsets(&hctx, 0, sizeof(hctx));
	flen = 0;
	mnum = 0;
	fclose(f);

	return ret;
#undef READ
#undef WRITE
#undef SEEK
#undef MACCHK
}

int undel_load(struct user *u, struct umessage **messages) {
#define READ(buf, size) do {\
	if(fread(buf, size, 1, f) != 1) {\
		ERR("failed to read from file: %s", path);\
		goto err;\
	}\
} while(0)

#define MACCHK() do {\
	if(memcmp_ct(macc, macf, 0x20) != 0) {\
		ERR("invalid mac in %s", path);\
		goto err;\
	}\
} while(0)

	int ret = -1;

	char *path = undel_path(u);
	if(path == NULL) {
		ERR("failed to allocate memory");
		return -1;
	}
	FILE *f = fopen(path, "rb");
	if(f == NULL) {
		ERR("failed to open file: %s", path);
		goto err;
	}

	uint8_t macc[0x20], *macf;
	uint8_t prefix[0x30];
	uint8_t prev_mac[0x20];
	uint8_t len_buf[8];

	HMAC_SHA256_CTX hctx;
	struct umessage *head = NULL;

	READ(prefix, 0x30);

	hmac_sha256(u->und_auth, 32, prefix, 0x10, macc);
	macf = &prefix[0x10];

	MACCHK();

	uint64_t mnum = decbe64(&prefix[8]);

	memcpy(prev_mac, INITIAL_PREV_MAC, 0x20);

	struct umessage **cur = &head;
	macf = prev_mac;
	for(uint64_t i = 0; i < mnum; i++) {
		READ(len_buf, 8);

		uint64_t len = decbe64(len_buf);

		struct umessage *m = alloc_umessage(len);
		m->len = len;
		READ(m->message, len);

		hmac_sha256_init(&hctx, u->und_auth, 0x20);
		hmac_sha256_update(&hctx, prev_mac, 0x20);
		hmac_sha256_update(&hctx, len_buf, 8);
		hmac_sha256_update(&hctx, m->message, len);
		hmac_sha256_final(&hctx, macc);

		READ(macf, 0x20);

		MACCHK();

		*cur = m;
		cur = &m->next;
	}

	*cur = NULL;

	*messages = head;

	ret = undel_init_file(u);
err:
	free(path);
	memsets(macc, 0, sizeof(macc));
	memsets(prefix, 0, sizeof(prefix));
	memsets(prev_mac, 0, sizeof(prev_mac));
	memsets(len_buf, 0, sizeof(len_buf));
	memsets(&hctx, 0, sizeof(hctx));
	mnum = 0;
	fclose(f);

	return ret;
}

struct umessage *alloc_umessage(uint64_t len) {
	struct umessage *m = malloc(sizeof(*m));
	if(m == NULL) {
		return NULL;
	}
	m->message = malloc(len);
	if(m->message == NULL) {
		free(m);
		return NULL;
	}
	m->len = len;
	m->next = NULL;
	return m;
}

void free_umessage(struct umessage *m) {
	zfree(m->message, m->len);
	free(m);
}

void free_umessage_list(struct umessage *m) {
	while(m) {
		struct umessage *n = m->next;
		free_umessage(m);
		m = n;
	}
}

int undel_init(char *root_dir) {
	UNDEL_DIR = malloc(strlen(root_dir) + strlen(UNDEL_DIR_SUFFIX) + 1);
	if(UNDEL_DIR == NULL) {
		return 1;
	}

	strcpy(UNDEL_DIR, root_dir);
	strcat(UNDEL_DIR, UNDEL_DIR_SUFFIX);

	return check_undel_dir();
}

