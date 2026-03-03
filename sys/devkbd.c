/*
 * Marrow Keyboard Device (/dev/kbd)
 * C89/C90 compliant
 *
 * Simple keyboard device for marrow
 */

#include "lib9p.h"
#include "libregistry.h"  /* For service_get, service_free_info */
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
 * Forward keyboard event to Kryon WM's virtual device
 * Returns: number of bytes forwarded, or 0 if WM not running
 */
static ssize_t forward_to_wm_kbd(const char *buf, size_t count)
{
    ServiceInfo *svc;
    P9Node *wm_tree;
    P9Node *kbd_node;
    ssize_t result;

    /* Get Kryon WM service from registry */
    svc = service_get("kryon");
    if (svc == NULL) {
        /* WM not running - this is OK, just ignore */
        return 0;
    }

    /* Navigate to /win/1/dev/kbd in WM's tree */
    wm_tree = svc->tree;
    if (wm_tree == NULL) {
        service_free_info(svc);
        return 0;
    }

    /* Look up the keyboard device node */
    kbd_node = tree_lookup(wm_tree, "/win/1/dev/kbd");
    if (kbd_node == NULL) {
        /* Window 1 might not exist yet - OK */
        service_free_info(svc);
        return 0;
    }

    /* Forward the write to WM's vdev handler */
    result = node_write(kbd_node, buf, count, 0);

    /* Cleanup */
    service_free_info(svc);

    return result;
}

/*
 * Write handler for /dev/kbd
 * Forwards keyboard events to Kryon WM if running
 */
static ssize_t devkbd_write(const char *buf, size_t count, uint64_t offset, void *data)
{
    (void)offset;
    (void)data;

    if (buf == NULL || count == 0) {
        return 0;
    }

    /* Forward to WM's virtual keyboard device */
    /* If WM is not running, this gracefully returns 0 and we accept the write */
    forward_to_wm_kbd(buf, count);

    /* Always accept the write */
    return count;
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
