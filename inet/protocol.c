#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <ibcrypt/sha256.h>

#include <libibur/endian.h>

#include "message.h"
#include "protocol.h"

//#define PROTO_DEBUG

#define WAIT_TIMEOUT (50000)
#define ACK_WAITTIME (5000000ULL)

#define INBUF_SIZE (4096)

/* error handling */
#ifndef PROTO_DEBUG
#define IO_CHECK(x, y) {                                                       \
	if((x) == -1) { goto error; }                                          \
	if((x) != (y)) { errno = ETIME; goto error; }                          \
}
#else
#define IO_CHECK(x, y) {                                                       \
        if((x) == -1) { goto error; }                                          \
        if((x) != (y)) { fprintf(stderr, "%d: IO_CHECK failed\n", __LINE__);   \
                errno = ETIME; goto error;}                                    \
}
#endif

#define ACK_MAP_MASK 0xff
#define ACK_MAP_FAIL ((uint64_t)-1)

struct ack_map_el;
struct ack_map {
	struct ack_map_el *lists[ACK_MAP_MASK + 1];
};

struct ack_map_el {
	uint64_t seq_num;
	uint64_t time;
	struct ack_map_el *next;
};

static int ack_map_add(struct ack_map *map, uint64_t seq_num, uint64_t time);
static int ack_map_rm(struct ack_map *map, uint64_t seq_num);
static uint64_t ack_map_get(struct ack_map *map, uint64_t seq_num);

static int write_messages(struct con_handle *con, struct ack_map *map);
static int read_message(struct con_handle *con, struct ack_map *map);
static ssize_t send_bytes(int fd, void *buf, size_t len, int flags, uint64_t timeout);
static ssize_t read_bytes(int fd, void *buf, size_t len, int flags, uint64_t timeout);
static int write_keepalive(struct con_handle *con);
static int write_acknowledge(struct con_handle *con, uint64_t seq_num);
static int acknowledge_add(struct ack_map *map, uint64_t seq_num);

uint64_t utime(struct timeval tv) {
	return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

/* you may NOT own the kill_mutex mutex when you call this function */
void end_handler(struct con_handle *con) {
	pthread_mutex_lock(&con->kill_mutex);
	con->kill = 1;
	pthread_mutex_unlock(&con->kill_mutex);
}

/* you may NOT own the kill_mutex mutex when you call this function */
int handler_status(struct con_handle *con) {
	int s;
	pthread_mutex_lock(&con->kill_mutex);
	s = con->kill;
	pthread_mutex_unlock(&con->kill_mutex);
	return s;
}


void init_handler(struct con_handle *con, int sockfd) {
	con->sockfd = sockfd;
	con->out_queue = EMPTY_MESSAGE_QUEUE;
	con->in_queue = EMPTY_MESSAGE_QUEUE;
	pthread_mutex_init(&con->out_mutex, NULL);
	pthread_mutex_init(&con->in_mutex, NULL);
	pthread_mutex_init(&con->kill_mutex, NULL);
	con->ka_last_recv = 0;
	con->kill = 0;
}

void destroy_handler(struct con_handle *con) {
	pthread_mutex_destroy(&con->out_mutex);
	pthread_mutex_destroy(&con->in_mutex);
	pthread_mutex_destroy(&con->kill_mutex);
}

struct message *get_message(struct con_handle *con, uint64_t timeout) {
	struct timeval start, now;
	gettimeofday(&start, NULL);
	now = start;
	uint64_t waittime = timeout < WAIT_TIMEOUT ? timeout : WAIT_TIMEOUT;
	struct message *m = NULL;
	while(handler_status(con) == 0 &&
		(timeout == 0 || utime(now) - utime(start) < timeout)) {
		pthread_mutex_lock(&con->in_mutex);
		if(con->in_queue.size > 0) {
			m = message_queue_pop(&con->in_queue);

			goto exit;
		}
		pthread_mutex_unlock(&con->in_mutex);
		usleep(waittime);

		gettimeofday(&now, NULL);
	}

	errno = ETIME;
exit:
	return m;
}

void add_message(struct con_handle *con, struct message *m) {
	pthread_mutex_lock(&con->out_mutex);
	message_queue_push(&con->out_queue, m);
	pthread_mutex_unlock(&con->out_mutex);
}

static void handler_cleanup(void *_con) {
	struct con_handle *con = ((struct con_handle *) _con);
	end_handler(con);
}

/* handles a connection to the client or server, made to be run as a thread */
/* _con should be of type connection */
void *handle_connection(void *_con) {
	pthread_cleanup_push(handler_cleanup, _con);
	struct con_handle *con = ((struct con_handle *) _con);
	struct ack_map map;

	uint8_t inbuf[INBUF_SIZE + 1];

	fd_set rset;
	fd_set wset;
	struct timeval select_wait;
	struct timeval now;

	uint64_t ka_last_sent;

	gettimeofday(&now, NULL);
	ka_last_sent = utime(now);
	con->ka_last_recv = ka_last_sent;

	size_t i;
	struct ack_map_el *el;

	int ret;

	memset(&map, 0, sizeof(map));

	while(1) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		FD_SET(con->sockfd, &rset);
		FD_SET(con->sockfd, &wset);
		select_wait.tv_sec = 0;
		select_wait.tv_usec = WAIT_TIMEOUT;

		if(select(FD_SETSIZE, &rset, &wset, NULL, &select_wait) == -1) {
#ifdef PROTO_DEBUG
			fprintf(stderr, "%d: select error: %s\n", __LINE__,
				strerror(errno));
#endif
			continue;
		}

		if(FD_ISSET(con->sockfd, &rset)) {
			ret = pthread_mutex_trylock(&con->in_mutex);
			if(ret != 0) {
				if(ret != EBUSY) {
#ifdef PROTO_DEBUG
					fprintf(stderr, "%d: mutex lock error: %s\n",
						__LINE__, strerror(errno));
#endif
					goto error;
				}

				goto endread;
			}

			ret = read_message(con, &map);
			if(ret != 0) {
				pthread_mutex_unlock(&con->in_mutex);
				goto error;
			}

			pthread_mutex_unlock(&con->in_mutex);
		}
		endread:;

		if(FD_ISSET(con->sockfd, &wset)) {
			ret = pthread_mutex_trylock(&con->out_mutex);
			if(ret != 0) {
				if(ret != EBUSY) {
#ifdef PROTO_DEBUG
					fprintf(stderr, "%d: mutex lock error: %s\n",
						__LINE__, strerror(errno));
#endif
					goto error;
				}

				goto endwrite;
			}

			if(con->out_queue.size > 0) {
				ret = write_messages(con, &map);
				if(ret != 0) {
					pthread_mutex_unlock(&con->out_mutex);
#ifdef PROTO_DEBUG
					printf("connection closed\n");
#endif
					goto error;
				}
			}

			pthread_mutex_unlock(&con->out_mutex);
		}
		endwrite:;

		/* check the acknowledges to make sure we're not overrun now */
		gettimeofday(&now, NULL);
		uint64_t earliest_ack = utime(now) - ACK_WAITTIME;

		for(i = 0; i <= ACK_MAP_MASK; i++) {
			el = map.lists[i];
			while(el != NULL) {
				if(el->time < earliest_ack) {
#ifdef PROTO_DEBUG
					printf("%llu acknowledge not received "
					       "in time\n", el->seq_num);
#endif
					errno = ETIME;
					goto error;
				}

				el = el->next;
			}
		}

		if(utime(now) - ACK_WAITTIME > con->ka_last_recv) {
#ifdef PROTO_DEBUG
			printf("keep alive not received in time\n");
#endif
			errno = ETIME;
			goto error;
		}

		if(utime(now) - ACK_WAITTIME / 2 > ka_last_sent) {
			ret = write_keepalive(con);
			if(ret == -1) {
				goto error;
			}
			ka_last_sent = utime(now);
		}

		if(handler_status(con) != 0) {
			/* we have received the kill signal */
			goto exit;
		}
	}

error:
#ifdef PROTO_DEBUG
	perror("connection error");
#endif
	end_handler(con);
exit:
	close(con->sockfd);
	pthread_cleanup_pop(0);
	return NULL;
}

static int write_messages(struct con_handle *con, struct ack_map *map) {
	/* buffer for message type, ending zeroes, etc. */
	uint8_t buf[8];
	uint8_t hash[32];
	ssize_t written;
	ssize_t total;
	while(con->out_queue.size > 0) {
		struct message *next_message = message_queue_top(&con->out_queue);

		/* calculate sha256 hash */
		sha256(next_message->message, next_message->length, hash);

		/* give writing the type 5ms */
		encbe32(2, buf);
		written = send_bytes(con->sockfd, buf, 4, 0, 5000ULL);
		IO_CHECK(written, 4);

		/* write seqnum */
		encbe64(next_message->seq_num, buf);
		/* limit seqnum writing to 10ms */
		written = send_bytes(con->sockfd, buf, 8, 0, 10000ULL);
		IO_CHECK(written, 8);
		/* write length */
		encbe64(next_message->length, buf);
		/* limit length writing to 10ms */
		written = send_bytes(con->sockfd, buf, 8, 0, 10000ULL);
		IO_CHECK(written, 8);

		/* leave 50ms to write the message, we don't want to take too
		 * long */
		written = send_bytes(con->sockfd, next_message->message,
			next_message->length, 0, 50000ULL);
		IO_CHECK(written, next_message->length);

		/* write the hash */
		written = send_bytes(con->sockfd, hash, 32, 0, 10000ULL);
		IO_CHECK(written, 32);

		/* add the ack */
		if(acknowledge_add(map, next_message->seq_num) == -1) {
			goto error;
		}

		message_queue_pop(&con->out_queue);
		free_message(next_message);

#ifdef PROTO_DEBUG
		printf("%llu sent\n", next_message->seq_num);
#endif
	}

exit:
	return 0;
error:
	return -1;
}

static int read_message(struct con_handle *con, struct ack_map *map) {
	uint8_t buf[8];
	uint8_t hash1[32];
	uint8_t hash2[32];
	ssize_t received;

	uint32_t type;

	struct message *in_message;
	uint64_t seq_num, length;

	struct timeval now;

	received = read_bytes(con->sockfd, buf, 4, 0, 5000ULL);
	IO_CHECK(received, 4);

	type = decbe32(buf);
	switch(type) {
	case 1: /* ACK */
		received = read_bytes(con->sockfd, buf, 8, 0, 10000ULL);
		IO_CHECK(received, 8);
		if(ack_map_rm(map, decbe64(buf)) == -1) {
#ifdef PROTO_DEBUG
			fprintf(stderr, "ack_map doesn't contain key\n");
#endif
			errno = EINVAL;
			goto error;
		}
#ifdef PROTO_DEBUG
		printf("%llu ack'ed\n", decbe64(buf));
#endif
		break;
	case 3: /* KA */
		gettimeofday(&now, NULL);
		con->ka_last_recv = utime(now);
#ifdef PROTO_DEBUG
		printf("ka received\n");
#endif
		break;
	case 2: /* new message */
		received = read_bytes(con->sockfd, buf, 8, 0, 10000ULL);
		IO_CHECK(received, 8);
		seq_num = decbe64(buf);

		received = read_bytes(con->sockfd, buf, 8, 0, 10000ULL);
		IO_CHECK(received, 8);
		length = decbe64(buf);

		if((in_message = alloc_message(length)) == NULL) {
			goto error;
		}

		in_message->seq_num = seq_num;
		in_message->length = length;

		received = read_bytes(con->sockfd, in_message->message,
			in_message->length, 0, 50000ULL);
		IO_CHECK(received, in_message->length);

		received = read_bytes(con->sockfd, hash1, 32, 0, 10000ULL);
		IO_CHECK(received, 32);

		sha256(in_message->message, in_message->length, hash2);
		if(memcmp(hash1, hash2, 32) != 0) {
			errno = EPROTO;
			goto error;
		}

		if(message_queue_push(&con->in_queue, in_message) == -1) {
			goto error;
		}

		if(write_acknowledge(con, in_message->seq_num) == -1) {
			goto error;
		}
#ifdef PROTO_DEBUG
		printf("%llu ack sent\n", in_message->seq_num);
#endif
		break;
	default:
#ifdef PROTO_DEBUG
		fprintf(stderr, "invalid type value: %llu\n", (uint64_t)type);
#endif
		errno = EINVAL;
		goto error;
	}

exit:
	return 0;
error:
	return -1;
}

/* sends the message using non-blocking operations
 * aborts after timeout (microseconds) has passed */
static ssize_t send_bytes(int fd, void *buf, size_t len, int flags, uint64_t timeout) {
	struct timeval start, cur;
	gettimeofday(&start, NULL);
	uint64_t timediff;

	size_t total = 0;
	ssize_t written;

	struct timeval wait;
	fd_set wset;

	do {
		FD_ZERO(&wset);
		FD_SET(fd, &wset);
		wait.tv_sec = 0;
		wait.tv_usec = WAIT_TIMEOUT < timeout ? WAIT_TIMEOUT : timeout;

		if(select(FD_SETSIZE, NULL, &wset, NULL, &wait) == -1) {
#ifdef PROTO_DEBUG
			fprintf(stderr, "%d: select error: %s\n", __LINE__,
				strerror(errno));
#endif
			goto error;
		}

		written = send(fd, &buf[total], len - total, flags | MSG_DONTWAIT);
		if(written == -1) {
			if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
#ifdef PROTO_DEBUG
				fprintf(stderr, "%d: socket write error: %s\n",
					__LINE__, strerror(errno));
#endif
				goto error;
			}
			goto loopend;
		}

		total += written;
	loopend:
		gettimeofday(&cur, NULL);
		timediff = utime(cur) - utime(start);
	} while(timediff < timeout && total < len);

	return total;
error:
	return -1;
}

/* reads the message using non-blocking operations
 * aborts after timeout (microseconds) */
static ssize_t read_bytes(int fd, void *buf, size_t len, int flags, uint64_t timeout) {
	struct timeval start, cur;
	gettimeofday(&start, NULL);
	uint64_t timediff;

	size_t total = 0;
	ssize_t received = 0;

	struct timeval wait;
	fd_set rset;

	do {
		FD_ZERO(&rset);
		FD_SET(fd, &rset);
		wait.tv_sec = 0;
		wait.tv_usec = WAIT_TIMEOUT < timeout ? WAIT_TIMEOUT : timeout;

		if(select(FD_SETSIZE, &rset, NULL, NULL, &wait) == -1) {
#ifdef PROTO_DEBUG
			fprintf(stderr, "%d: select error: %s\n", __LINE__,
				strerror(errno));
#endif
			goto error;
		}

		received = recv(fd, &buf[total], len - total, flags | MSG_DONTWAIT);
		if(received == -1) {
			if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
#ifdef PROTO_DEBUG
				fprintf(stderr, "%d: socket read error: %s\n",
					__LINE__, strerror(errno));
#endif
				goto error;
			}
			goto loopend;
		}

		total += received;
	loopend:
		gettimeofday(&cur, NULL);
		timediff = utime(cur) - utime(start);
	} while(timediff < timeout && total < len);

	return total;
error:
	return -1;
}

static int write_keepalive(struct con_handle *con) {
	uint8_t buf[4];
	ssize_t written;

	encbe32(3, buf);
	written = send_bytes(con->sockfd, buf, 4, 0, 5000ULL);
	IO_CHECK(written, 4);

exit:
	return 0;
error:
	return -1;
}

static int write_acknowledge(struct con_handle *con, uint64_t seq_num) {
	uint8_t buf[8];
	ssize_t written;

	encbe32(1, buf);
	written = send_bytes(con->sockfd, buf, 4, 0, 5000ULL);
	IO_CHECK(written, 4);

	encbe64(seq_num, buf);
	written = send_bytes(con->sockfd, buf, 8, 0, 5000ULL);
	IO_CHECK(written, 8);

exit:
	return 0;
error:
	return -1;
}

static int acknowledge_add(struct ack_map *map, uint64_t seq_num) {
	struct timeval now;
	gettimeofday(&now, NULL);

	return ack_map_add(map, seq_num, utime(now));
}

/* values to be acknowledged map implementation */
static int ack_map_add(struct ack_map *map, uint64_t seq_num, uint64_t time) {
	struct ack_map_el *next;

	if((next = malloc(sizeof(struct ack_map_el))) == NULL) {
		errno = ENOMEM;
		return -1;
	}

	next->seq_num = seq_num;
	next->time = time;
	next->next = NULL;

	struct ack_map_el **loc = &map->lists[seq_num & ACK_MAP_MASK];
	while(*loc != NULL) {
		loc = &((*loc)->next);
	}

	*loc = next;

	return 0;
}

static int ack_map_rm(struct ack_map *map, uint64_t seq_num) {
	struct ack_map_el **prev;
	struct ack_map_el *el;

	prev = &map->lists[seq_num & ACK_MAP_MASK];
	el = *prev;

	while(el != NULL) {
		if(el->seq_num == seq_num) {
			*prev = el->next;
			free(el);
			return 0;
		}
		prev = &el->next;
		el = el->next;
	}

	return -1;
}

static uint64_t ack_map_get(struct ack_map *map, uint64_t seq_num) {
	struct ack_map_el *el;

	el = map->lists[seq_num & ACK_MAP_MASK];

	while(el != NULL) {
		if(el->seq_num == seq_num) {
			return el->time;
		}
	}

	return ACK_MAP_FAIL;
}

