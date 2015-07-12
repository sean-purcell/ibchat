/* contains a hash table containing user data */
/* see dirstructure.txt */

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <sys/stat.h>

#include <libibur/endian.h>

#include <ibcrypt/rsa.h>
#include <ibcrypt/rsa_util.h>
#include <ibcrypt/sha256.h>

#include "user_db.h"

#include "chat_server.h"

#define TOP_LOAD (0.75)
#define BOT_LOAD (0.5 / 2)

#define MAX_SIZE ((uint64_t)1 << 20)
#define MIN_SIZE ((uint64_t) 16)

#define MAX_READERS INT_MAX - 1

static const char *USER_DIR_SUFFIX = "/users/";

static char *USER_DIR;

static const char USER_FILE_MAGIC[8] = "userdb\0\0";

struct user_db_ent {
	struct user u;
	struct user_db_ent *next;
};

struct user_db_st {
	struct user_db_ent **buckets;
	uint64_t size;

	uint64_t elements;

	/* the use state indicates whether it can be written to/read from */
	/* see server/client_handler.c for a similar example */
	pthread_mutex_t use_state_mutex;
	pthread_cond_t use_state_cond;
	int use_state;
} db;

static uint64_t hash_id(uint8_t *id) {
	uint8_t shasum[32];
	sha256(id, 32, shasum);

	return  decbe64(&id[ 0]) ^
	        decbe64(&id[ 8]) ^
	        decbe64(&id[16]) ^
		decbe64(&id[24]);
}

static uint64_t hash(struct user *u) {
	return hash_id(u->uid);
}

static int init_user_db_st() {
	size_t size = MIN_SIZE * sizeof(struct user_db_ent *);
	db.buckets = malloc(size);
	if(db.buckets == NULL) {
		return 1;
	}
	memset(db.buckets, 0, size);

	db.size = MIN_SIZE;
	db.elements = 0;

	db.use_state = 0;
	if(pthread_cond_init(&db.use_state_cond, NULL) != 0) {
		return 1;
	}
	if(pthread_mutex_init(&db.use_state_mutex, NULL) != 0) {
		return 1;
	}

	return 0;
}

static int resize() {
	uint64_t nsize = db.size;
	if(db.size < MAX_SIZE &&
		(uint64_t) (db.elements / TOP_LOAD) > db.size) {
		db.size *= 2;
	}
	if(db.size > MIN_SIZE &&
		(uint64_t) (db.elements / BOT_LOAD) < db.size) {
		db.size /= 2;
	}

	if(nsize == db.size) {
		return 0;
	}

	size_t bufsize = nsize * sizeof(struct user_db_ent *);
	struct user_db_ent **nbuckets = malloc(bufsize);
	if(nbuckets == NULL) {
		return 1;
	}
	memset(nbuckets, 0, bufsize);

	for(uint64_t i = 0; i < db.size; i++) {
		struct user_db_ent *cur = db.buckets[i];
		struct user_db_ent *next;
		while(cur != NULL) {
			next = cur->next;
			uint64_t nidx = hash(&cur->u) % nsize;
			cur->next = nbuckets[nidx];
			nbuckets[nidx] = cur;
			cur = next;
		}
	}

	free(db.buckets);
	db.buckets = nbuckets;
	db.size = nsize;

	return 0;
}

static int user_db_add(struct user u) {
	uint64_t idx = hash(&u) % db.size;

	struct user_db_ent *ent = malloc(sizeof(struct user_db_ent));
	if(ent == NULL) {
		return 1;
	}

	ent->u = u;
	struct user_db_ent *bucket = db.buckets[idx];
	ent->next = bucket;
	db.buckets[idx] = ent;

	db.elements++;

	return resize();
}

static int check_user_dir() {
	struct stat st = {0};
	if(stat(USER_DIR, &st) == -1) {
		if(errno != ENOENT) {
			fprintf(stderr, "failed to open user directory: %s\n", USER_DIR);
			return -1;
		}

		/* directory doesn't exist, create it */
		if(mkdir(USER_DIR, 0700) != 0) {
			fprintf(stderr, "failed to create user directory: %s\n", USER_DIR);
			return -1;
		}
	} else {
		/* make sure its a directory */
		if(!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "specified user directory is not a directory: %s\n", USER_DIR);
			return -1;
		}
	}
	return 0;
}

static int parse_user_file(char *name, struct user *user) {
#define ERR() do { fprintf(stderr, "invalid user file: %s\n", name);\
	goto err; } while(0);
#define READ(f, b, s)                                            \
        if(fread(b, s, 1, f) != 1) {                             \
		ERR();                                           \
        }

	FILE *uf = fopen(name, "rb");
	if(uf == NULL) {
		fprintf(stderr, "failed to open user file: %s\n", name);
		return 1;
	}

	uint8_t prefix[8 + 0x20 + 0x20 + 8];
	uint8_t *magic = prefix;
	uint8_t *uid = magic + 8;
	uint8_t *undelivered = uid + 0x20;
	uint8_t *sizebuf = undelivered + 0x20;
	RSA_PUBLIC_KEY pkey;

	uint8_t *buf = NULL;
	uint8_t *sigbuf = NULL;

	uint64_t pkey_size;

	memset(&pkey, 0, sizeof(pkey));

	READ(uf, magic, 8);
	if(memcmp(magic, USER_FILE_MAGIC, 8) != 0) {
		ERR();
	}

	READ(uf, uid, 0x20);
	READ(uf, undelivered, 0x20);

	READ(uf, sizebuf, 8);

	uint64_t siglen = (server_pub_key.bits + 7) / 8;
	sigbuf = malloc(siglen);
	if(sigbuf == NULL) {
		ERR();
	}

	READ(uf, sigbuf, siglen);

	/* the key length is signed so that we know that the length
	 * hasn't been tampered with */
	int valid = 0;
	if(rsa_pss_verify(&server_pub_key, sigbuf, siglen, prefix, 0x50, &valid) != 0) {
		ERR();
	}
	if(!valid) {
		ERR();
	}

	pkey_size = decbe64(sizebuf);

	buf = malloc(0x50 + siglen + pkey_size);
	if(buf == NULL) {
		ERR();
	}

	uint8_t *pkey_buf = buf + 0x50 + siglen;

	/* read in the public key */
	READ(uf, buf, pkey_size);

	/* copy the other data into the buffer */
	memcpy(buf, prefix, 0x50);
	memcpy(buf + 0x50, sigbuf, siglen);

	/* read in the signature, same key so same size as previous */
	READ(uf, sigbuf, siglen);

	/* verify again before unpacking public key */
	if(rsa_pss_verify(&server_pub_key, sigbuf, siglen, buf, 0x50 + siglen + pkey_size, &valid) != 0) {
		ERR();
	}
	if(!valid) {
		ERR();
	}

	if(rsa_wire2pubkey(pkey_buf, pkey_size, &pkey) != 0) {
		ERR();
	}

	/* public keys can be passed by value */
	user->pkey = pkey;
	memcpy(user->uid, uid, 0x20);
	memcpy(user->undel, undelivered, 0x20);

	int ret = 0;
	goto exit;
err:
	ret = 1;
exit:
	fclose(uf);
	if(ret) rsa_free_pubkey(&pkey); /* if we succeeded we don't want to destroy the public key */
	if(sigbuf) free(sigbuf);
	if(buf) free(buf);
	/* none of this is sensitive so we don't need to zero it */

	return ret;
}

static int load_user_files() {
	if(check_user_dir() != 0) {
		return 1;
	}

	DIR *userdir = opendir(USER_DIR);
	if(userdir == NULL) {
		fprintf(stderr, "failed to open userdir: %s\n", USER_DIR);
		return 1;
	}

	size_t upathlen = strlen(USER_DIR);
	char *path = malloc(upathlen + 64 + 1);
	path[upathlen + 64] = '\0';
	if(path == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		return 1;
	}

	struct dirent *ent;
	char *name;
	while((ent = readdir(userdir)) != NULL) {
		name = ent->d_name;
		if(name[0] == '.') {
			continue;
		}
		if(strlen(name) != 64) {
			/* names are hex versions of sha256 hashes
			 * so they are 64 characters long */
			fprintf(stderr, "unrecognised file in user dir: %s\n", name);
			continue;
		}
		int valid = 1;
		for(int i = 0; i < 64; i++) {
			valid &= ((name[i] >= '0' && name[i] <= '9') ||
			          (name[i] >= 'a' && name[i] <= 'f'));
			path[upathlen + i] = name[i];
		}
		if(!valid) {
			fprintf(stderr, "unrecognised file in user dir: %s\n", name);
			continue;
		}
		printf("loading user file %s\n", name);

		struct user u;

		if(parse_user_file(path, &u) != 0) {
			fprintf(stderr, "failed to parse user file: %s\n", name);
			continue;
		}

		/* add it to the struct */
		if(user_db_add(u) != 0) {
			fprintf(stderr, "failed to add user to struct: %s\n", name);
		}
	}

	return 0;
}

static int init_user_dir(char *root_dir) {
	USER_DIR = malloc(strlen(root_dir) + strlen(USER_DIR_SUFFIX) + 1);
	if(USER_DIR == NULL) {
		return 1;
	}

	strcpy(USER_DIR, root_dir);
	strcpy(USER_DIR + strlen(root_dir), USER_DIR_SUFFIX);

	return 0;
}

int init_user_db(char *root_dir) {
	/* set up the table */
	if(init_user_db_st() != 0) {
		return 1;
	}

	if(init_user_dir(root_dir) != 0) {
		return 1;
	}

	/* add all existing user files */
	if(load_user_files() != 0) {
		return 1;
	}

	return 0;
}

