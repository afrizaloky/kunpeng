#ifndef KUNPENG_OPENSSL_PLATFORM_H
#define KUNPENG_OPENSSL_PLATFORM_H
/* No process environment or filesystem is exposed to OpenSSL. */
#define getenv kunpeng_getenv
#define stat kunpeng_stat
#include <time.h>
time_t kunpeng_time(time_t *out);
int kunpeng_nanosleep(const struct timespec *req, struct timespec *remaining);
int kunpeng_clock_gettime(clockid_t clock, struct timespec *ts);
#define time(out) kunpeng_time(out)
#define gettimeofday kunpeng_gettimeofday
#define clock_gettime kunpeng_clock_gettime
#define nanosleep kunpeng_nanosleep
#define getpid kunpeng_getpid
#endif
