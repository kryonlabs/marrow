/*
 * Marrow Time Device (/dev/time, /dev/nsec)
 * C89/C90 compliant
 *
 * Read-only device that returns current Unix timestamp as ASCII.
 * Plan 9 style: read /dev/time to get the current time.
 * /dev/nsec returns monotonic nanoseconds (used by p9sys_nsec).
 */

#define _POSIX_C_SOURCE 199309L  /* for struct timespec, clock_gettime */

/* Include system headers FIRST to avoid plan9port macro conflicts */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Now include plan9port headers */
#include <lib9.h>

/* Include local headers */
#include "lib9p.h"

/*
 * CRITICAL: Undefine plan9port's localtime macro.
 * This file uses POSIX localtime for time conversion.
 */
#ifdef localtime
#undef localtime
#endif

/*
 * Read handler for /dev/time
 * Returns current Unix timestamp followed by newline
 */
static ssize_t devtime_read(char *buf, size_t count, uint64_t offset, void *fid_ctx)
{
    char tbuf[32];
    int len;

    len = snprint(tbuf, sizeof(tbuf), "%ld\n", (long)time(NULL));
    if (len < 0) return -1;

    if (offset >= (uint64_t)len) return 0;
    if (offset + count > (uint64_t)len) count = (size_t)(len - (int)offset);

    memcpy(buf, tbuf + offset, count);
    return (ssize_t)count;
}

/*
 * Write handler for /dev/time - read-only device
 */
static ssize_t devtime_write(const char *buf, size_t count, uint64_t offset, void *fid_ctx)
{
    (void)buf;
    (void)count;
    (void)offset;
    return -1;
}

/*
 * Read handler for /dev/date
 * Returns today's date as YYYY-MM-DD followed by newline
 */
static ssize_t devdate_read(char *buf, size_t count, uint64_t offset, void *fid_ctx)
{
    char tbuf[16];
    int len;
    time_t t;
    struct tm *tm;

    t = time(NULL);
    tm = localtime(&t);
    if (tm == NULL) return -1;
    len = snprint(tbuf, sizeof(tbuf), "%04d-%02d-%02d\n",
                   tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    if (len < 0) return -1;
    if (offset >= (uint64_t)len) return 0;
    if (offset + count > (uint64_t)len) count = (size_t)(len - (int)offset);
    memcpy(buf, tbuf + offset, count);
    return (ssize_t)count;
}

/*
 * Read handler for /dev/nsec
 * Returns monotonic nanoseconds as ASCII, for use by p9sys_nsec.
 */
static ssize_t devnsec_read(char *buf, size_t count, uint64_t offset, void *fid_ctx)
{
    char tbuf[32];
    int len;
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    len = snprint(tbuf, sizeof(tbuf), "%lld\n",
                   (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec);
    if (len < 0) return -1;

    if (offset >= (uint64_t)len) return 0;
    if (offset + count > (uint64_t)len) count = (size_t)(len - (int)offset);

    memcpy(buf, tbuf + offset, count);
    return (ssize_t)count;
}

/*
 * Initialize /dev/time, /dev/date, and /dev/nsec
 */
int devtime_init(P9Node *dev_dir)
{
    P9Node *time_file;
    P9Node *date_file;
    P9Node *nsec_file;

    if (dev_dir == NULL) {
        return -1;
    }

    time_file = tree_create_file(dev_dir, "time", NULL,
                                  devtime_read,
                                  devtime_write);
    if (time_file == NULL) {
        return -1;
    }

    date_file = tree_create_file(dev_dir, "date", NULL,
                                  devdate_read,
                                  NULL);  /* read-only */
    if (date_file == NULL) {
        return -1;
    }

    nsec_file = tree_create_file(dev_dir, "nsec", NULL,
                                  devnsec_read,
                                  NULL);  /* read-only */
    if (nsec_file == NULL) {
        return -1;
    }

    fprintf(stderr, "devtime_init: initialized /dev/time, /dev/date, /dev/nsec\n");
    return 0;
}
