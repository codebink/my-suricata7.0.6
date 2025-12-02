#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>

#define DEBUG_LOG_ROOT_DIR "/SE/"
#define DEBUG_LOG_PATH "/SE/log/"
#define DEBUG_LOG_FILE "/SE/log/debug_log.txt"
//#define ENABLE_DECODER_DEBUG_DEBUG
#ifdef ENABLE_DECODER_DEBUG_DEBUG
#define DEBUG_DLOG(fmt, ...) \
	do{ \
		if (0 != access(DEBUG_LOG_PATH, F_OK)) { \
			mkdir(DEBUG_LOG_ROOT_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH); \
			mkdir(DEBUG_LOG_PATH, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH); \
		} \
		if (0 == access(DEBUG_LOG_PATH, F_OK)) { \
			FILE *gl_fd = fopen(DEBUG_LOG_FILE, "a+"); \
			fprintf(gl_fd, "(%s:%d) DEBUG: " fmt "\n", \
				__FILE__, __LINE__, ##__VA_ARGS__); \
			fflush(gl_fd); \
			fclose(gl_fd); \
		} \
	}while (0)

#define DEBUG_DLOG_ZY(str, map) \
	do{ \
		char buff[4096*2]; \
		zysnprintf(buff, sizeof(buff), "${1@MPJ}\n",map); \
		DEBUG_DLOG("%s:%s", str, buff); \
	}while (0)

#define DEBUG_DLOG_DATA(fmt, ...) \
	do{ \
		if (0 != access(DEBUG_LOG_PATH, F_OK)) { \
			mkdir(DEBUG_LOG_ROOT_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH); \
			mkdir(DEBUG_LOG_PATH, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH); \
		} \
		if (0 == access(DEBUG_LOG_PATH, F_OK)) { \
			FILE *gl_fd = fopen(DEBUG_LOG_FILE, "a+"); \
			fprintf(gl_fd, fmt,  ##__VA_ARGS__); \
			fflush(gl_fd); \
			fclose(gl_fd); \
		} \
	}while (0)

#else
#define DEBUG_DLOG(fmt, ...)
#define DEBUG_DLOG_ZY(str, map)
#define DEBUG_DLOG_DATA(fmt, ...)
#endif

#endif /* DEBUG_LOG_H */
