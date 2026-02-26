#ifndef DRAWCONN_STUB_H
#define DRAWCONN_STUB_H

#include "lib9p.h"

/* Stub for graphics functionality - marrow doesn't include graphics */
/* This will be provided by kryon when it connects as a service */

P9Node *drawconn_create_dir(int conn_id);
int devdraw_new_init(P9Node *draw_dir);
int devscreen_init(P9Node *dev_dir, void *screen);
void devscreen_cleanup(void);
int devmouse_init(P9Node *dev_dir);
int devkbd_init(P9Node *dev_dir);
int drawconn_init(void *screen);
void drawconn_cleanup(void);

#endif
