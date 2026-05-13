#ifndef MOCK_ANDROID_LOG_H
#define MOCK_ANDROID_LOG_H

#include <stdio.h>
#include <stdarg.h>

#define ANDROID_LOG_INFO 4
#define ANDROID_LOG_WARN 3
#define ANDROID_LOG_ERROR 2
#define ANDROID_LOG_DEBUG 3

static inline void __android_log_print(int prio, const char* tag, const char* fmt, ...) {
    (void)prio;
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[%s] ", tag);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

#endif
