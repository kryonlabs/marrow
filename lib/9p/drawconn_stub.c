/*
 * Marrow - Graphics Connection Stubs
 * C89/C90 compliant
 *
 * These functions are stubs for graphics functionality.
 * In marrow, graphics are provided by external services (e.g., kryon).
 */

#include "drawconn_stub.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Stub for drawconn_create_dir
 * In marrow, this returns NULL since graphics are handled by kryon
 */
P9Node *drawconn_create_dir(int conn_id)
{
    (void)conn_id;
    fprintf(stderr, "drawconn_create_dir: graphics not available in marrow (use kryon service)\n");
    return NULL;
}

/*
 * Stub for devdraw_new_init
 */
int devdraw_new_init(P9Node *draw_dir)
{
    (void)draw_dir;
    fprintf(stderr, "devdraw_new_init: graphics not available in marrow (use kryon service)\n");
    return -1;
}

/*
 * Stub for devscreen_init
 */
int devscreen_init(P9Node *dev_dir, void *screen)
{
    (void)dev_dir;
    (void)screen;
    fprintf(stderr, "devscreen_init: graphics not available in marrow (use kryon service)\n");
    return -1;
}

/*
 * Stub for devscreen_cleanup
 */
void devscreen_cleanup(void)
{
    /* No-op in marrow */
}

/*
 * Stub for devmouse_init
 */
int devmouse_init(P9Node *dev_dir)
{
    (void)dev_dir;
    fprintf(stderr, "devmouse_init: graphics not available in marrow (use kryon service)\n");
    return -1;
}

/*
 * Stub for devkbd_init
 */
int devkbd_init(P9Node *dev_dir)
{
    (void)dev_dir;
    fprintf(stderr, "devkbd_init: graphics not available in marrow (use kryon service)\n");
    return -1;
}

/*
 * Stub for drawconn_init
 */
int drawconn_init(void *screen)
{
    (void)screen;
    fprintf(stderr, "drawconn_init: graphics not available in marrow (use kryon service)\n");
    return -1;
}

/*
 * Stub for drawconn_cleanup
 */
void drawconn_cleanup(void)
{
    /* No-op in marrow */
}
