#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>

#include <sys/time.h>

#include "cli.h"
#include "ibchat_client.h"

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static void print_time() {
	char time[20];
	struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm *tm_info;

	tm_info = localtime(&tv.tv_sec);

	strftime(time, 26, "%Y-%m-%d %H:%M:%S", tm_info);
	fprintf(lgf, "%s:%.3d - ", time, tv.tv_usec / 1000);
	if(debug_mode) {
		fprintf(stderr, "%s:%.3d - ", time, tv.tv_usec / 1000);
	}
}

void LOG(char *format, ...) {
	pthread_mutex_lock(&log_lock);
	print_time();
	va_list args;
	va_start(args, format);
	vfprintf(lgf, format, args);
	fflush(lgf);
	va_end(args);
	if(debug_mode) {
		va_start(args, format);
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
	pthread_mutex_unlock(&log_lock);
}

