/*
 * Marrow Mouse Device (/dev/mouse)
 * C89/C90 compliant
 *
 * Simple mouse device for marrow
 * Returns mouse events in Plan 9 format
 */

#include "lib9p.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mouse data buffer (reserved for future use) */
/* static char mouse_buf[1024]; */
/* static int mouse_buf_len; */

/*
 * Read handler for /dev/mouse
 * Returns mouse events in Plan 9 format: "m x y buttons\n"
 */
static ssize_t devmouse_read(char *buf, size_t count, uint64_t offset, void *data)
{
    (void)data;

    /* For now, return no mouse data */
    if (offset >= 0) {
        return 0;
    }

    /* Plan 9 mouse format: "m x y buttons\n" */
    if (count > 0) {
        strcpy(buf, "m 0 0 0\n");  /* No mouse movement */
        return strlen(buf);
    }

    return 0;
}

/*
 * Write handler for /dev/mouse (not implemented)
 */
static ssize_t devmouse_write(const char *buf, size_t count, uint64_t offset, void *data)
{
    (void)buf;
    (void)offset;
    (void)data;
    return count;  /* Accept writes but ignore */
}

/*
 * Initialize /dev/mouse
 */
int devmouse_init(P9Node *dev_dir)
{
    P9Node *mouse_file;

    if (dev_dir == NULL) {
        return -1;
    }

    mouse_file = tree_create_file(dev_dir, "mouse", NULL,
                                  devmouse_read,
                                  devmouse_write);
    if (mouse_file == NULL) {
        return -1;
    }

    fprintf(stderr, "devmouse_init: initialized /dev/mouse\n");
    return 0;
}
