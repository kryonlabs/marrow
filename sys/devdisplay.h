#ifndef _DEVDISPLAY_H
#define _DEVDISPLAY_H

#include "lib9p.h"

/* Initialize /dev/display device */
extern int devdisplay_init(P9Node *dev_dir);

/* Cleanup display device */
extern void devdisplay_cleanup(void);

#endif
