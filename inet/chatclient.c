#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pthread.h>

#define PORT "3490"

#ifdef __linux__
# define TCP_KEEPALIVE_IDLE TCP_KEEPIDLE
# define TCP_KEEPALIVE_INTERVAL TCP_KEEPINTVL
# define TCP_KEEPALIVE_COUNT TCP_KEEPCNT
#endif
#if defined(__APPLE__) && defined(__MACH__)
# define TCP_KEEPALIVE_IDLE TCP_KEEPALIVE
# define TCP_KEEPALIVE_INTERVAL TCP_KEEPINTVL
# define TCP_KEEPALIVE_COUNT TCP_KEEPCNT
#endif

void chat(int sockfd) {
	const int BUFLEN = 128;
	char buf[BUFLEN + 1];

	fd_set rset;
	fd_set eset;
	struct timeval wait;

	while(1) {
		FD_ZERO(&rset);
		FD_SET(STDIN_FILENO, &rset);
		FD_SET(sockfd, &rset);
		FD_ZERO(&eset);
		FD_SET(STDIN_FILENO, &eset);
		FD_SET(sockfd, &eset);
		wait.tv_sec = 0;
		wait.tv_usec = 50000;

		if(select(FD_SETSIZE, &rset, NULL, &eset, &wait) == -1) {
			perror("client: select");
			continue;
		}

		if(FD_ISSET(STDIN_FILENO, &rset) || FD_ISSET(STDIN_FILENO, &eset)) {
			ssize_t lread = read(STDIN_FILENO, buf, BUFLEN);

			if(lread == -1) {
				perror("client: stdin read err");
				continue;
			}

			buf[lread]  = '\0';

			ssize_t total = 0;
			while(total < lread) {
				ssize_t written = send(sockfd, &buf[total], lread - total, 0);
				if(written == 0) {
					perror("client: write err");
					continue;
				}
				total += written;
			}

			printf("wrote %s", buf);
		}
		if(FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &eset)) {
			ssize_t lread = recv(sockfd, buf, BUFLEN, 0);

			if(lread == -1) {
				perror("client: socket read err");
				continue;
			} else if(lread == 0) {
				printf("connection closed\n");
				close(sockfd);
				return;
			}

			buf[lread] = '\0';

			printf("read %s", buf);
		}
	}

	close(sockfd);
}

int main(int argc, char **argv) {
	signal(SIGPIPE, SIG_IGN);

	if(argc != 2) {
		printf("usage: %s <address>\n", argv[0]);
		return -1;
	}

	int ret;

	struct addrinfo hints;
	struct addrinfo *servinfo;
	struct addrinfo *server;

	socklen_t sin_size;

	char ip[INET_ADDRSTRLEN];

	int sockfd;

	memset(&hints, 0x00, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if((ret = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo err: %s", gai_strerror(ret));
		return 1;
	}

	for(server = servinfo; server != NULL; server = server->ai_next) {
		if((sockfd = socket(server->ai_family, server->ai_socktype,
			server->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if(connect(sockfd, server->ai_addr, server->ai_addrlen) != 0) {
			close(sockfd);
			perror("client: connect");
			continue;
		}
		break;
	}

	if(server == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 1;
	}

	freeaddrinfo(servinfo);

	puts("ready to communicate");

	const char *s = inet_ntop(server->ai_family, &((struct sockaddr_in*)(server->ai_addr))->sin_addr,
		ip, sizeof(ip));
	if(!s) {
		perror("client: get address");
		return -1;
	}
	printf("client: connected to %s\n", s);

	int idle = 1;
	int intvl = 1;
	int cnt = 4;
	int yes = 1;
	if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE_IDLE, &idle, sizeof(idle)) != 0) {
		perror("client: setsockopt");
	}
	if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE_INTERVAL, &intvl, sizeof(intvl)) != 0) {
		perror("client: setsockopt");
	}
	if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE_COUNT, &cnt, sizeof(cnt)) != 0) {
		perror("client: setsockopt");
	}
	if(setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) != 0) {
		perror("client: setsockopt");
	}

	chat(sockfd);
}

