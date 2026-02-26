/*
 * Marrow Keyboard Device (/dev/kbd)
 * C89/C90 compliant
 *
 * Simple keyboard device for marrow
 */

#include "lib9p.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Keyboard data buffer (reserved for future use) */
/* static char kbd_buf[4096]; */
/* static int kbd_buf_len; */

/*
 * Read handler for /dev/kbd
 * Returns key events in Plan 9 format
 */
static ssize_t devkbd_read(char *buf, size_t count, uint64_t offset, void *data)
{
    (void)data;

    /* For now, return no keyboard data */
    if (offset >= 0) {
        return 0;
    }

    /* Plan 9 kbd format: character or escape sequence */
    if (count > 0) {
        buf[0] = 0;  /* No key available */
        return 1;
    }

    return 0;
}

/*
 * Write handler for /dev/kbd (not implemented)
 */
static ssize_t devkbd_write(const char *buf, size_t count, uint64_t offset, void *data)
{
    (void)buf;
    (void)offset;
    (void)data;
    return count;  /* Accept writes but ignore */
}

/*
 * Initialize /dev/kbd
 */
int devkbd_init(P9Node *dev_dir)
{
    P9Node *kbd_file;

    if (dev_dir == NULL) {
        return -1;
    }

    kbd_file = tree_create_file(dev_dir, "kbd", NULL,
                                 devkbd_read,
                                 devkbd_write);
    if (kbd_file == NULL) {
        return -1;
    }

    fprintf(stderr, "devkbd_init: initialized /dev/kbd\n");
    return 0;
}
