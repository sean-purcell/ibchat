#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pthread.h>

#define PORT "3490"

void *handle_connection(void *arg) {
	int sockfd = *((int *)arg);

	fd_set set;
	struct timeval wait;

	const size_t BUFSIZE = 1024;
	char buf[BUFSIZE + 1];
	buf[BUFSIZE] = '\0';

	wait.tv_sec = 0;
	wait.tv_usec = 50000;

	printf("new connection handler opened for sockfd %d\n", sockfd);
	while(1) {
		FD_ZERO(&set);
		FD_SET(sockfd, &set);
		select(FD_SETSIZE, &set, NULL, &set, &wait);

		ssize_t read = recv(sockfd, buf, BUFSIZE, 0);
		if(read == -1) {
			perror("read error");
		} else if(read == 0) {
			close(sockfd);
			FD_ZERO(&set);
			printf("handler for sockfd %d exiting\n", sockfd);
			return NULL;
		}
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

		printf("%d: %s", sockfd, buf);
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

		pthread_t thread;

		pthread_create(&thread, NULL, handle_connection, &new_fd);
	}
}

