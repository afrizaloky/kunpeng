#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <tee_time_api.h>

char *kunpeng_getenv(const char *name)
{
    (void)name;
    return NULL;
}

int kunpeng_stat(const char *path, struct stat *buf)
{
    (void)path;
    (void)buf;
    errno = ENOSYS;
    return -1;
}

time_t kunpeng_time(time_t *out)
{
    TEE_Time now;
    get_sys_rtc_time(&now);
    if (out != NULL)
        *out = (time_t)now.seconds;
    return (time_t)now.seconds;
}

int kunpeng_gettimeofday(struct timeval *tv, void *zone)
{
    TEE_Time now;
    (void)zone;
    get_sys_rtc_time(&now);
    tv->tv_sec = now.seconds;
    tv->tv_usec = now.millis * 1000;
    return 0;
}

int kunpeng_clock_gettime(clockid_t clock, struct timespec *ts)
{
    TEE_Time now;
    if (clock == CLOCK_REALTIME)
        get_sys_rtc_time(&now);
    else if (clock == CLOCK_MONOTONIC)
        TEE_GetSystemTime(&now);
    else {
        errno = EINVAL;
        return -1;
    }
    ts->tv_sec = now.seconds;
    ts->tv_nsec = now.millis * 1000000L;
    return 0;
}

int kunpeng_nanosleep(const struct timespec *req, struct timespec *remaining)
{
    uint64_t ms;
    if (req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec >= 1000000000L) {
        errno = EINVAL;
        return -1;
    }
    ms = (uint64_t)req->tv_sec * 1000 + (req->tv_nsec + 999999) / 1000000;
    if (ms >= UINT32_MAX) {
        errno = EINVAL;
        return -1;
    }
    if (TEE_Wait((uint32_t)ms) != TEE_SUCCESS) {
        if (remaining != NULL)
            *remaining = *req;
        errno = EINTR;
        return -1;
    }
    return 0;
}

pid_t kunpeng_getpid(void)
{
    /* A single-instance TA cannot fork; OpenSSL uses this only for fork detection. */
    return 1;
}
