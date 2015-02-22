#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "protocol.h"
#include "../util/message.h"

int main() {
	pthread_t thread;

	struct connection con;
	con.sockfd = 1;
	pthread_create(&thread, NULL, handle_connection, &con);
}

