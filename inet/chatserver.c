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

void *handle_connection(void *arg) {
	int sockfd = *((int *)arg);

	const size_t BUFSIZE = 1024;
	char buf[BUFSIZE + 1];
	buf[BUFSIZE] = '\0';

	printf("new connection handler opened for sockfd %d\n", sockfd);
	while(1) {
		ssize_t read = recv(sockfd, buf, BUFSIZE, 0);
		if(read == -1) {
			perror("read error");
		} else if(read == 0) {
			close(sockfd);
			printf("handler for sockfd %d exiting\n", sockfd);
			return NULL;
		} else {
			buf[read] = '\0';

			size_t total = 0;
			while(total < read) {
				ssize_t written = send(sockfd, &buf[total], read - total, 0);
				if(written == -1) {
					perror("write error");
					printf("%d, %zu, %zd, %s\n", sockfd, total, read, buf);
				}
				total += written;
			}

			printf("%d: ", sockfd);
			size_t i;
			for(i = 0; i < read; i++) {
				if(!iscntrl(buf[i])) {
					putchar(buf[i]);
				}
			}
			puts("");
		}
	}
}

int main(int argc, char **argv) {
	signal(SIGPIPE, SIG_IGN);

	int ret;

	struct addrinfo hints;
	struct addrinfo *servinfo;
	struct addrinfo *server;

	struct sockaddr_storage client_address;
	socklen_t sin_size;

	char ip[INET_ADDRSTRLEN];

	int sockfd;

	memset(&hints, 0x00, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; /* local ip */

	if((ret = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo err: %s", gai_strerror(ret));
		return 1;
	}

	for(server = servinfo; server != NULL; server = server->ai_next) {
		if((sockfd = socket(server->ai_family, server->ai_socktype,
			server->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		int yes = 1;
		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
			sizeof(int)) == -1) {
			perror("server: setsockopt");
			exit(1);
		}

		if(bind(sockfd, server->ai_addr, server->ai_addrlen) == -1) {
			perror("server: bind");
			continue;
		}

		break;
	}

	if(server == NULL) {
		fprintf(stderr, "server: failed to bind\n");
		return 1;
	}

	freeaddrinfo(servinfo);

	if(listen(sockfd, 20) == -1) {
		perror("server: sigaction:");
		return 1;
	}

	printf("ready for conections\n");

	while(1) {
		sin_size = sizeof(client_address);
		int new_fd = accept(sockfd, (struct sockaddr*) &client_address, &sin_size);

		if(new_fd == -1) {
			perror("server: accept");
			continue;
		}

		const char *s = inet_ntop(client_address.ss_family, &(((struct sockaddr_in*) &client_address)->sin_addr),
			ip, sizeof(ip));
		if(!s) {
			perror("server: get address");
			continue;
		}
		printf("server: connection from %s\n", s);

		int idle = 1;
		int intvl = 1;
		int cnt = 4;
		int yes = 1;
		if(setsockopt(new_fd, IPPROTO_TCP, TCP_KEEPALIVE_IDLE, &idle, sizeof(idle)) != 0) {
			perror("server: setsockopt");
		}
		if(setsockopt(new_fd, IPPROTO_TCP, TCP_KEEPALIVE_INTERVAL, &intvl, sizeof(intvl)) != 0) {
			perror("server: setsockopt");
		}
		if(setsockopt(new_fd, IPPROTO_TCP, TCP_KEEPALIVE_COUNT, &cnt, sizeof(cnt)) != 0) {
			perror("server: setsockopt");
		}
		if(setsockopt(new_fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) != 0) {
			perror("server: setsockopt");
		}

		pthread_t thread;

		pthread_create(&thread, NULL, handle_connection, &new_fd);
	}
}

