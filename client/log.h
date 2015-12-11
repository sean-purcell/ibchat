#ifndef CLIENT_LOG_H
#define CLIENT_LOG_H

#define LOGLINE() LOG("DEBUG %s:%d", __FILE__, __LINE__)

void LOG(char *format, ...);

#endif

