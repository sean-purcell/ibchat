#ifndef CLIENT_LOG_H
#define CLIENT_LOG_H

#define LOGLINE() LOG("DEBUG %s:%d", __FILE__, __LINE__)
#define ERRLINE() do {\
	ERR("ERROR %s:%d", __FILE__, __LINE__);\
	exit(1);\
} while(0)

void LOG(char *format, ...);
void ERR(char *format, ...);

#endif

