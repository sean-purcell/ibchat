#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <ibcrypt/sha256.h>

#include <libibur/endian.h>

#include "../util/message.h"
#include "protocol.h"

#define WAIT_TIMEOUT (50000)
#define ACK_WAITTIME (5)

#define INBUF_SIZE (4096)

static int write_messages(struct connection *con);
static ssize_t send_bytes(int fd, void *buf, size_t len, int flags, uint64_t timeout);

/* handles a connection to the client or server, made to be run as a thread */
/* _con should be of type connection */
void *handle_connection(void *_con) {
	struct connection *con = ((struct connection *) _con);

	uint8_t inbuf[INBUF_SIZE + 1];

	fd_set rset;
	fd_set wset;
	struct timeval select_wait;

	int ret;

	while(1) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		FD_SET(con->sockfd, &rset);
		FD_SET(con->sockfd, &wset);
		select_wait.tv_sec = 0;
		select_wait.tv_usec = WAIT_TIMEOUT;

		if(select(FD_SETSIZE, &rset, &wset, NULL, &select_wait) == -1) {
			fprintf(stderr, "%d: select error: %s\n", __LINE__,
				strerror(errno));
			continue;
		}

		if(FD_ISSET(con->sockfd, &rset)) {
			/* handle incoming read */
			printf("read ready\n");

			uint8_t a;
			ssize_t recved = recv(con->sockfd, &a, 1, 0);
			if(recved == 0) {
				goto exit;
			}
		}
		endread:;

		if(FD_ISSET(con->sockfd, &wset)) {
			ret = pthread_mutex_trylock(&con->out_mutex);
			if(ret == -1) {
				if(errno != EBUSY) {
					fprintf(stderr, "%d: mutex lock error: %s\n",
						__LINE__, strerror(errno));
					perror("mutex lock error");
					goto endwrite;
				}
			}

			if(con->out_queue.size > 0) {
				ret = write_messages(con);
				if(ret != 0) {
					goto exit;
				}
			}

			pthread_mutex_unlock(&con->out_mutex);
		}
		endwrite:;
	}

exit:
	puts("exiting");
	close(con->sockfd);
	return NULL;
}

static int write_messages(struct connection *con) {
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
		if((written = send_bytes(con->sockfd, buf, 4, 0, 5000ULL))
			== -1) {
			goto error;
		}

		if(written != 4) {
			errno = ETIME;
			goto error;
		}

		/* write seqnum */
		encbe64(next_message->seq_num, buf);
		/* limit seqnum writing to 10ms */
		if((written = send_bytes(con->sockfd, buf, 8, 0, 10000ULL))
			== -1) {
			goto error;
		}
		if(written != 8) {
			errno = ETIME;
			goto error;
		}
		/* write length */
		encbe64(next_message->length, buf);
		/* limit length writing to 10ms */
		if((written = send_bytes(con->sockfd, buf, 8, 0, 10000ULL))
			== -1) {
			goto error;
		}
		if(written != 8) {
			errno = ETIME;
			goto error;
		}

		/* leave 50ms to write the message, we don't want to take too
		 * long */
		written = send_bytes(con->sockfd, next_message->message,
			next_message->length, 0, 50000ULL);
		if(written == -1) {
			goto error;
		}
		if(written != next_message->length) {
			errno = ETIME;
			goto error;
		}

		/* write the hash */
		if((written = send_bytes(con->sockfd, hash, 32, 0, 10000ULL))
			== -1) {
			goto error;
		}
		if(written != 32) {
			errno = ETIME;
			goto error;
		}

		message_queue_pop(&con->out_queue);
	}

exit:
	return 0;
error:
	return -1;
}

/* sends the message using non-blocking operations
 * aborts after timeout (nanoseconds) has passed */
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
		wait.tv_usec = WAIT_TIMEOUT < timeout / 1000 ? WAIT_TIMEOUT : timeout / 1000;

		if(select(FD_SETSIZE, NULL, &wset, NULL, &wait) == -1) {
			fprintf(stderr, "%d: select error: %s\n", __LINE__,
				strerror(errno));
			goto error;
		}

		written = send(fd, buf, len, flags | MSG_DONTWAIT);
		if(written == -1) {
			if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
				fprintf(stderr, "%d: socket write error: %s\n",
					__LINE__, strerror(errno));
				goto error;
			}
			goto loopend;
		}

		total += written;
	loopend:
		gettimeofday(&cur, NULL);
		timediff =
			((uint64_t)cur.tv_sec * 1000000ULL + cur.tv_usec) - 
			((uint64_t)start.tv_sec * 1000000ULL + start.tv_usec);
	} while(timediff < timeout && total < len);

	return total;
error:
	return -1;
}

