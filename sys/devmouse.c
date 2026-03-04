/*
 * Marrow Mouse Device (/dev/mouse)
 * C89/C90 compliant
 *
 * Simple mouse device for marrow
 * Returns mouse events in Plan 9 format
 */

#include "lib9p.h"
#include "libregistry.h"  /* For service_get, service_free_info */
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
static ssize_t devmouse_read(char *buf, size_t count, uint64_t offset)
{
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
 * Forward mouse event to Kryon WM's virtual device
 * Returns: number of bytes forwarded, or 0 if WM not running
 */
static ssize_t forward_to_wm_mouse(const char *buf, size_t count)
{
    ServiceInfo *svc;
    P9Node *wm_tree;
    P9Node *mouse_node;
    ssize_t result;

    /* Get Kryon WM service from registry */
    svc = service_get("kryon");
    if (svc == NULL) {
        /* WM not running - this is OK, just ignore */
        return 0;
    }

    /* Navigate to /win/1/dev/mouse in WM's tree */
    wm_tree = svc->tree;
    if (wm_tree == NULL) {
        service_free_info(svc);
        return 0;
    }

    /* Look up the mouse device node */
    mouse_node = tree_lookup(wm_tree, "/win/1/dev/mouse");
    if (mouse_node == NULL) {
        /* Window 1 might not exist yet - OK */
        service_free_info(svc);
        return 0;
    }

    /* Forward the write to WM's vdev handler */
    result = node_write(mouse_node, buf, count, 0);

    /* Cleanup */
    service_free_info(svc);

    return result;
}

/*
 * Write handler for /dev/mouse
 * Forwards mouse events to Kryon WM if running
 */
static ssize_t devmouse_write(const char *buf, size_t count, uint64_t offset)
{
    (void)offset;

    if (buf == NULL || count == 0) {
        return 0;
    }

    /* Forward to WM's virtual mouse device */
    /* If WM is not running, this gracefully returns 0 and we accept the write */
    forward_to_wm_mouse(buf, count);

    /* Always accept the write */
    return count;
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
