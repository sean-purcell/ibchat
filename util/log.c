#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>

#include <sys/time.h>

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static char time_str[30];

static FILE *lgf = NULL;
static int debug_mode = 0;

void set_logfile(FILE *f) {
	lgf = f;
}

void set_debug_mode(int dbm) {
	debug_mode = dbm;
}

static void fmt_time() {
	char time[20];
	struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm *tm_info;

	tm_info = localtime(&tv.tv_sec);

	strftime(time, 26, "%Y-%m-%d %H:%M:%S", tm_info);
	sprintf(time_str, "%s:%.3d - ", time, tv.tv_usec / 1000);
}

static void write_to_file(FILE *f, char *format, va_list args) {
	if(f == NULL) return;
	va_list arg_copy;
	va_copy(arg_copy, args);
	fputs(time_str, f);
	vfprintf(f, format, arg_copy);
	fputs("\n", f);
	fflush(f);
	va_end(arg_copy);
}

static void write_message(int log, int err, char *format, va_list args) {
	pthread_mutex_lock(&log_lock);
	fmt_time();
	if(log) {
		write_to_file(lgf, format, args);
	}
	if(err) {
		write_to_file(stderr, format, args);
	}
	pthread_mutex_unlock(&log_lock);
}

void LOG(char *format, ...) {
	va_list args;
	va_start(args, format);
	write_message(1, debug_mode, format, args);
	va_end(args);
}

void ERR(char *format, ...) {
	va_list args;
	va_start(args, format);
	write_message(1, 1, format, args);
	va_end(args);
}

