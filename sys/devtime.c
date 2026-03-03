/*
 * Marrow Time Device (/dev/time)
 * C89/C90 compliant
 *
 * Read-only device that returns current Unix timestamp as ASCII.
 * Plan 9 style: read /dev/time to get the current time.
 */

#include "lib9p.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Read handler for /dev/time
 * Returns current Unix timestamp followed by newline
 */
static ssize_t devtime_read(char *buf, size_t count, uint64_t offset, void *data)
{
    char tbuf[32];
    int len;
    (void)data;

    len = snprintf(tbuf, sizeof(tbuf), "%ld\n", (long)time(NULL));
    if (len < 0) return -1;

    if (offset >= (uint64_t)len) return 0;
    if (offset + count > (uint64_t)len) count = (size_t)(len - (int)offset);

    memcpy(buf, tbuf + offset, count);
    return (ssize_t)count;
}

/*
 * Write handler for /dev/time - read-only device
 */
static ssize_t devtime_write(const char *buf, size_t count, uint64_t offset, void *data)
{
    (void)buf;
    (void)count;
    (void)offset;
    (void)data;
    return -1;
}

/*
 * Read handler for /dev/date
 * Returns today's date as YYYY-MM-DD followed by newline
 */
static ssize_t devdate_read(char *buf, size_t count, uint64_t offset, void *data)
{
    char tbuf[16];
    int len;
    time_t t;
    struct tm *tm;
    (void)data;
    t = time(NULL);
    tm = localtime(&t);
    if (tm == NULL) return -1;
    len = snprintf(tbuf, sizeof(tbuf), "%04d-%02d-%02d\n",
                   tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    if (len < 0) return -1;
    if (offset >= (uint64_t)len) return 0;
    if (offset + count > (uint64_t)len) count = (size_t)(len - (int)offset);
    memcpy(buf, tbuf + offset, count);
    return (ssize_t)count;
}

/*
 * Initialize /dev/time and /dev/date
 */
int devtime_init(P9Node *dev_dir)
{
    P9Node *time_file;
    P9Node *date_file;

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

    fprintf(stderr, "devtime_init: initialized /dev/time and /dev/date\n");
    return 0;
}
