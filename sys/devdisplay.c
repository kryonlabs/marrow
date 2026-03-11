/*
 * Kryon Display Coordination Device
 * C89/C90 compliant
 *
 * /dev/display/ctl - Coordinates display client size
 * WM writes: "WIDTHxHEIGHT\n"
 * Display client reads: "WIDTHxHEIGHT\n"
 */

#include "lib9p.h"
#include <lib9.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Display state
 */
typedef struct {
    int width;
    int height;
    int initialized;
} DisplayState;

static DisplayState g_display_state = {0};

/*
 * Read from /dev/display/ctl
 * Returns "WIDTHxHEIGHT\n"
 */
static ssize_t devdisplay_read(char *buf, size_t count, uint64_t offset,
                               void *data)
{
    char size_str[64];
    int len;
    
    (void)data;
    (void)offset;
    
    /* Format: "WIDTHxHEIGHT\n" */
    len = snprint(size_str, sizeof(size_str), "%dx%d\n",
                  g_display_state.width, g_display_state.height);
    
    if (len < 0 || len >= (int)sizeof(size_str)) {
        return -1;
    }
    
    /* Handle offset */
    if (offset >= (uint64_t)len) {
        return 0;  /* EOF */
    }
    
    /* Calculate bytes to return */
    if (offset + count > (uint64_t)len) {
        count = len - (size_t)offset;
    } else {
        /* count already correct */
    }
    
    memcpy(buf, size_str + offset, count);
    return (ssize_t)count;
}

/*
 * Write to /dev/display/ctl
 * Accepts: "WIDTHxHEIGHT\n"
 */
static ssize_t devdisplay_write(const char *buf, size_t count, uint64_t offset,
                                void *data)
{
    char cmd[64];
    size_t cmd_len;
    int width, height;
    
    (void)data;
    (void)offset;
    
    if (buf == NULL || count == 0 || count >= sizeof(cmd)) {
        return -1;
    }
    
    /* Copy and null-terminate */
    cmd_len = count < sizeof(cmd) - 1 ? count : sizeof(cmd) - 1;
    memcpy(cmd, buf, cmd_len);
    cmd[cmd_len] = '\0';
    
    /* Strip trailing newline */
    if (cmd_len > 0 && cmd[cmd_len - 1] == '\n') {
        cmd[cmd_len - 1] = '\0';
    }
    
    /* Parse "WIDTHxHEIGHT" */
    if (sscanf(cmd, "%dx%d", &width, &height) != 2) {
        fprintf(stderr, "devdisplay_write: invalid format '%s'\n", cmd);
        return -1;
    }
    
    if (width <= 0 || height <= 0) {
        fprintf(stderr, "devdisplay_write: invalid size %dx%d\n", width, height);
        return -1;
    }
    
    g_display_state.width = width;
    g_display_state.height = height;
    g_display_state.initialized = 1;
    
//     fprintf(stderr, "devdisplay: display size set to %dx%d\n", width, height);
    
    return count;
}

/*
 * Initialize /dev/display device
 */
int devdisplay_init(P9Node *dev_dir)
{
    P9Node *display_dir;
    P9Node *ctl_node;
    
    if (dev_dir == NULL) {
        return -1;
    }
    
    /* Create /dev/display directory */
    display_dir = tree_create_dir(dev_dir, "display");
    if (display_dir == NULL) {
        fprintf(stderr, "devdisplay_init: cannot create display directory\n");
        return -1;
    }
    
    /* Create /dev/display/ctl file */
    ctl_node = tree_create_file(display_dir, "ctl",
                               NULL,
                               (P9ReadFunc)devdisplay_read,
                               (P9WriteFunc)devdisplay_write);
    if (ctl_node == NULL) {
        fprintf(stderr, "devdisplay_init: cannot create ctl node\n");
        return -1;
    }
    
    /* Set default size (will be overwritten by WM) */
    g_display_state.width = 640;
    g_display_state.height = 480;
    g_display_state.initialized = 0;
    
    fprintf(stderr, "devdisplay_init: /dev/display/ctl ready\n");
    
    return 0;
}

/*
 * Cleanup display device
 */
void devdisplay_cleanup(void)
{
    g_display_state.width = 0;
    g_display_state.height = 0;
    g_display_state.initialized = 0;
}
