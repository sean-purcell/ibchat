#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
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

#include "../util/log.h"

//#define PROTO_DEBUG

#define WAIT_TIMEOUT (10000000ULL)
#define ACK_WAITTIME (100000000ULL)
#define READWRITE_WAIT (1000000ULL)

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
        if((x) != (y)) { ERR("%d: IO_CHECK failed", __LINE__);   \
                errno = ETIME; goto error;}                                    \
}
#endif

struct con_handle {
	int sockfd;
	struct message_queue out_queue;
	pthread_mutex_t out_mutex; /* mutex protecting the outgoing queue */
	struct message_queue in_queue;
	pthread_mutex_t in_mutex; /* mutex protecting the incoming queue */
	pthread_cond_t in_cond; /* condition variable to signal new message */
	int out_cond[2]; /* outgoing signal to indicate new message to send */
	uint64_t ka_last_recv; /* last time a keep-alive was received */
	pthread_mutex_t kill_mutex; /* mutex protecting the kill flag */
	int kill;
};

#define ACK_MAP_MASK 0xf

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

struct timeval tvtime(uint64_t utime) {
	struct timeval tv;
	tv.tv_sec = utime / 1000000ULL;
	tv.tv_usec = utime % 1000000ULL;

	return tv;
}

void init_handler(struct con_handle *con, int sockfd) {
	con->sockfd = sockfd;
	con->out_queue = EMPTY_MESSAGE_QUEUE;
	con->in_queue = EMPTY_MESSAGE_QUEUE;
	pthread_mutex_init(&con->out_mutex, NULL);
	pthread_mutex_init(&con->in_mutex, NULL);
	pthread_mutex_init(&con->kill_mutex, NULL);
	pthread_cond_init(&con->in_cond, NULL);
	pipe(con->out_cond);
	con->ka_last_recv = 0;
	con->kill = 0;
}

int launch_handler(pthread_t *thread, struct con_handle **_con, int fd) {
	struct con_handle *con = malloc(sizeof(struct con_handle));
	if(con == NULL) {
		return -1;
	}
	*_con = con;
	init_handler(con, fd);

	pthread_attr_t attr;
	if(pthread_attr_init(&attr) != 0) {
		return -1;
	}
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	if(pthread_create(thread, &attr, handle_connection, con) != 0) {
		return -1;
	}

	pthread_attr_destroy(&attr);

	return 0;
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

void destroy_handler(struct con_handle *con) {
	pthread_mutex_destroy(&con->out_mutex);
	pthread_mutex_destroy(&con->in_mutex);
	pthread_mutex_destroy(&con->kill_mutex);
	pthread_cond_destroy(&con->in_cond);
	close(con->out_cond[0]);
	close(con->out_cond[1]);

	free(con);
}

struct message *get_message(struct con_handle *con, uint64_t timeout) {
	struct timeval start, now;
	gettimeofday(&start, NULL);
	now = start;
	struct message *m = NULL;
	long waittime = (long long) (timeout != 0 && timeout < WAIT_TIMEOUT ?
		timeout : WAIT_TIMEOUT) * 1000;
	struct timespec wait;
	while(handler_status(con) == 0 &&
		(timeout == 0 || utime(now) - utime(start) < timeout)) {
		pthread_mutex_lock(&con->in_mutex);
		if(con->in_queue.size > 0) {
			m = message_queue_pop(&con->in_queue);

			pthread_mutex_unlock(&con->in_mutex);
			goto exit;
		}

		wait.tv_sec = now.tv_sec;
		wait.tv_nsec = (long long) now.tv_usec * 1000 + waittime;
		wait.tv_sec += wait.tv_nsec / 1000000000LL;
		wait.tv_nsec %= 1000000000LL;
#ifdef PROTO_DEBUG
		LOG("%d: entering wait", con->sockfd);
#endif
		pthread_cond_timedwait(&con->in_cond, &con->in_mutex, &wait);
#ifdef PROTO_DEBUG
		LOG("%d: exiting wait", con->sockfd);
#endif
		pthread_mutex_unlock(&con->in_mutex);

		gettimeofday(&now, NULL);
	}

	if(!(timeout == 0 || utime(now) - utime(start) < timeout)) {
#ifdef PROTO_DEBUG
		ERR("time elapsed to read message: %llu", timeout);
#endif

		errno = ETIME;
	} else {
#ifdef PROTO_DEBUG
		ERR("handler had non-zero kill status: %d", handler_status(con));
#endif

		errno = EPIPE;
	}
exit:
	return m;
}

void add_message(struct con_handle *con, struct message *m) {
	pthread_mutex_lock(&con->out_mutex);
	message_queue_push(&con->out_queue, m);

	char c = '\0';
	while(write(con->out_cond[1], &c, 1) != 1) {
		if(errno != EINTR) break;
		/* that shouldn't happen but we can't risk an infinite loop */
	}

#ifdef PROTO_DEBUG
	LOG("%d: wrote message and write flag", con->sockfd);
#endif

	pthread_mutex_unlock(&con->out_mutex);
}

static void handler_cleanup(void *_con) {
	struct con_handle *con = ((struct con_handle *) _con);
	end_handler(con);
	destroy_handler(con);
}

/* handles a connection to the client or server, made to be run as a thread */
/* _con should be of type connection */
void *handle_connection(void *_con) {
	pthread_cleanup_push(handler_cleanup, _con);
	struct con_handle *con = ((struct con_handle *) _con);
	struct ack_map map;

	fd_set rset;
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
		FD_SET(con->sockfd, &rset);
		FD_SET(con->out_cond[0], &rset);
		select_wait = tvtime(WAIT_TIMEOUT);

		if(select(FD_SETSIZE, &rset, NULL, NULL, &select_wait) == -1) {
#ifdef PROTO_DEBUG
			ERR("%d: select error: %s", __LINE__,
				strerror(errno));
#endif
			if(errno != EINTR) {
				goto error;
			}
		}

		if(FD_ISSET(con->sockfd, &rset)) {
			ret = pthread_mutex_trylock(&con->in_mutex);
			if(ret != 0) {
				if(ret != EBUSY) {
#ifdef PROTO_DEBUG
					ERR("%d: mutex lock error: %s",
						__LINE__, strerror(ret));
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

		if(FD_ISSET(con->out_cond[0], &rset)) {
#ifdef PROTO_DEBUG
			LOG("%d: out_cond flag set", con->sockfd);
#endif
			char c;
			while(read(con->out_cond[0], &c, 1) != 1) {
				if(errno != EINTR) break;
				/* should not happen */
			}
#ifdef NOTDEFED
		}
		/* we can't rely on the out_cond being set when a message is
		 * to be sent because write could have failed on the other end
		 */
		{
#endif
			ret = pthread_mutex_trylock(&con->out_mutex);
			if(ret != 0) {
				if(ret != EBUSY) {
#ifdef PROTO_DEBUG
					ERR("%d: mutex lock error: %s",
						__LINE__, strerror(ret));
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
					LOG("connection closed");
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
					LOG("%llu acknowledge not received "
					       "in time", el->seq_num);
#endif
					errno = ETIME;
					goto error;
				}

				el = el->next;
			}
		}

		if(utime(now) - ACK_WAITTIME > con->ka_last_recv) {
#ifdef PROTO_DEBUG
			LOG("keep alive not received in time");
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
	ERR("%d: handler exiting: %s", con->sockfd,
		strerror(errno));
#endif
exit:
	pthread_cleanup_pop(1);
	return NULL;
}

static int write_messages(struct con_handle *con, struct ack_map *map) {
	/* buffer for message type, ending zeroes, etc. */
	uint8_t buf[8];
	uint8_t hash[32];
	ssize_t written;

	struct timeval tv;
	uint64_t start;

	gettimeofday(&tv, NULL);
	start = utime(tv);

	while(con->out_queue.size > 0 && utime(tv) - start < ACK_WAITTIME / 2) {
		struct message *next_message = message_queue_top(&con->out_queue);

		const uint64_t total_time = READWRITE_WAIT;
		uint64_t end = utime(tv) + total_time;

		/* calculate sha256 hash */
		sha256(next_message->message, next_message->length, hash);

		encbe32(2, buf);
		gettimeofday(&tv, NULL);
		written = send_bytes(con->sockfd, buf, 4, 0, end - utime(tv));
		IO_CHECK(written, 4);

		/* write seqnum */
		encbe64(next_message->seq_num, buf);
		gettimeofday(&tv, NULL);
		written = send_bytes(con->sockfd, buf, 8, 0, end - utime(tv));
		IO_CHECK(written, 8);
		/* write length */
		encbe64(next_message->length, buf);
		gettimeofday(&tv, NULL);
		written = send_bytes(con->sockfd, buf, 8, 0, end - utime(tv));
		IO_CHECK(written, 8);

		gettimeofday(&tv, NULL);
		written = send_bytes(con->sockfd, next_message->message,
			next_message->length, 0, end - utime(tv));
		IO_CHECK(written, next_message->length);

		/* write the hash */
		gettimeofday(&tv, NULL);
		written = send_bytes(con->sockfd, hash, 32, 0, end - utime(tv));
		IO_CHECK(written, 32);

		/* add the ack */
		if(acknowledge_add(map, next_message->seq_num) == -1) {
			goto error;
		}

		message_queue_pop(&con->out_queue);
#ifdef PROTO_DEBUG
		LOG("%llu sent", next_message->seq_num);
#endif
		free_message(next_message);
		gettimeofday(&tv, NULL);
	}

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

	const uint64_t total_time = READWRITE_WAIT;
	uint64_t end;
	struct timeval now;

	gettimeofday(&now, NULL);
	end = total_time + utime(now);

	received = read_bytes(con->sockfd, buf, 4, 0, end - utime(now));
	IO_CHECK(received, 4);

	type = decbe32(buf);
	switch(type) {
	case 1: /* ACK */
		gettimeofday(&now, NULL);
		received = read_bytes(con->sockfd, buf, 8, 0, end - utime(now));
		IO_CHECK(received, 8);
		if(ack_map_rm(map, decbe64(buf)) == -1) {
#ifdef PROTO_DEBUG
			ERR("ack_map doesn't contain key");
#endif
			errno = EINVAL;
			goto error;
		}
#ifdef PROTO_DEBUG
		LOG("%llu ack'ed", decbe64(buf));
#endif
		break;
	case 3: /* KA */
		gettimeofday(&now, NULL);
		con->ka_last_recv = utime(now);
#ifdef PROTO_DEBUG
		LOG("ka received");
#endif
		break;
	case 2: /* new message */
		gettimeofday(&now, NULL);
		received = read_bytes(con->sockfd, buf, 8, 0, end - utime(now));
		IO_CHECK(received, 8);
		seq_num = decbe64(buf);

		gettimeofday(&now, NULL);
		received = read_bytes(con->sockfd, buf, 8, 0, end - utime(now));
		IO_CHECK(received, 8);
		length = decbe64(buf);

		if((in_message = alloc_message(length)) == NULL) {
			goto error;
		}

		in_message->seq_num = seq_num;
		in_message->length = length;

		gettimeofday(&now, NULL);
		received = read_bytes(con->sockfd, in_message->message,
			in_message->length, 0, end - utime(now));
		IO_CHECK(received, in_message->length);

		gettimeofday(&now, NULL);
		received = read_bytes(con->sockfd, hash1, 32, 0, end - utime(now));
		IO_CHECK(received, 32);

		sha256(in_message->message, in_message->length, hash2);
		if(memcmp(hash1, hash2, 32) != 0) {
			errno = EPROTO;
			goto error;
		}

		if(message_queue_push(&con->in_queue, in_message) == -1) {
			goto error;
		}
		pthread_cond_broadcast(&con->in_cond);

		if(write_acknowledge(con, in_message->seq_num) == -1) {
			goto error;
		}
#ifdef PROTO_DEBUG
		LOG("%llu ack sent", in_message->seq_num);
#endif
		break;
	default:
#ifdef PROTO_DEBUG
		ERR("invalid type value: %llu", (uint64_t)type);
#endif
		errno = EINVAL;
		goto error;
	}

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
		wait = tvtime(timeout < WAIT_TIMEOUT ? timeout : WAIT_TIMEOUT);

		if(select(FD_SETSIZE, NULL, &wset, NULL, &wait) == -1) {
#ifdef PROTO_DEBUG
			ERR("%d: select error: %s", __LINE__,
				strerror(errno));
#endif
			goto error;
		}

		written = send(fd, buf + total, len - total, flags | MSG_DONTWAIT);
		if(written == -1) {
			if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
#ifdef PROTO_DEBUG
				ERR("%d: socket write error: %s",
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
		wait = tvtime(timeout < WAIT_TIMEOUT ? timeout : WAIT_TIMEOUT);

		if(select(FD_SETSIZE, &rset, NULL, NULL, &wait) == -1) {
#ifdef PROTO_DEBUG
			ERR("%d: select error: %s", __LINE__,
				strerror(errno));
#endif
			goto error;
		}

		received = recv(fd, buf + total, len - total, flags | MSG_DONTWAIT);
		if(received == -1) {
			if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
#ifdef PROTO_DEBUG
				ERR("%d: socket read error: %s",
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
	written = send_bytes(con->sockfd, buf, 4, 0, 100000ULL);
	IO_CHECK(written, 4);

	return 0;
error:
	return -1;
}

static int write_acknowledge(struct con_handle *con, uint64_t seq_num) {
	uint8_t buf[8];
	ssize_t written;

	encbe32(1, buf);
	written = send_bytes(con->sockfd, buf, 4, 0, 100000ULL);
	IO_CHECK(written, 4);

	encbe64(seq_num, buf);
	written = send_bytes(con->sockfd, buf, 8, 0, 100000ULL);
	IO_CHECK(written, 8);

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

