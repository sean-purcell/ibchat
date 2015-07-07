/* contains a hash table containing user data */
/* see dirstructure.txt */

#include <dirent.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <libibur/endian.h>

#include <ibcrypt/sha256.h>

#define TOP_LOAD (0.75)
#define BOT_LOAD (0.5 / 2)

#define MAX_SIZE ((uint64_t)1 << 20)
#define MIN_SIZE ((uint64_t) 16)

#define MAX_READERS INT_MAX - 1

static const char *USER_DIR_SUFFIX = "users/";

static char *USER_DIR;

struct user_db_ent {
	struct user;
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

static int load_user_files() {
	DIR *userdir = NULL;

	userdir = opendir(USER_DIR);
	if(userdir == NULL) {
		fprintf(stderr, "failed to open userdir: %s\n", USER_DIR);
		return 1;
	}

	struct dirent *ent;
	while((ent = readdir(userdir)) != NULL) {
		printf("%s\n", ent->d_name);
	}

	hash_id(NULL);

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

