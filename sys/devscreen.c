/*
 * Kryon Graphics Engine - /dev/screen Device
 * C89/C90 compliant
 *
 * Exports the screen framebuffer as a read-only file
 */

#include "lib9p.h"
#include "graphics.h"
#include <lib9.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Screen device state
 */
typedef struct {
    Memimage *screen;    /* Screen framebuffer */
} ScreenState;

/*
 * Global screen state
 */
static ScreenState *g_screen_state = NULL;

/*
 * Global reference to /dev/screen/data node for resizing
 */
static P9Node *g_screen_data_node = NULL;

/*
 * Read from /dev/screen
 * Returns raw pixel data in RGBA32 format
 */
static ssize_t devscreen_read(char *buf, size_t count, uint64_t offset,
                              void *data)
{
    ScreenState *state = (ScreenState *)data;
    unsigned char *pixel_data;
    size_t total_size;
    size_t bytes_to_copy;

    if (state == NULL || state->screen == NULL) {
        return 0;
    }

    pixel_data = state->screen->data->bdata;
    total_size = Dx(state->screen->r) * Dy(state->screen->r) * 4;

    /* Verbose logging disabled - uncomment for debugging
    fprintf(stderr, "devscreen_read: offset=%lu count=%lu total_size=%lu\n",
            (unsigned long)offset, (unsigned long)count, (unsigned long)total_size);
    */

    if (offset >= total_size) {
        return 0;  /* EOF */
    }

    if (offset + count > total_size) {
        bytes_to_copy = total_size - offset;
    } else {
        bytes_to_copy = count;
    }

    memcpy(buf, pixel_data + offset, bytes_to_copy);

    /* Verbose logging disabled - uncomment for debugging
    fprintf(stderr, "devscreen_read: returning %lu bytes\n", (unsigned long)bytes_to_copy);
    */

    return bytes_to_copy;
}

/*
 * Write to /dev/screen
 * Allows writing raw pixel data to the screen framebuffer
 * This is a simplified interface for Kryon WM to update the screen
 */
static ssize_t devscreen_write(const char *buf, size_t count, uint64_t offset,
                               void *data)
{
    ScreenState *state = (ScreenState *)data;
    unsigned char *pixel_data;
    size_t total_size;
    size_t bytes_to_copy;
    static int first_write = 1;

    if (state == NULL || state->screen == NULL || buf == NULL) {
        return -1;
    }

    pixel_data = state->screen->data->bdata;
    total_size = Dx(state->screen->r) * Dy(state->screen->r) * 4;

    /* Verbose logging disabled - uncomment for debugging
    fprintf(stderr, "devscreen_write: offset=%lu count=%lu total_size=%lu\n",
            (unsigned long)offset, (unsigned long)count, (unsigned long)total_size);
    */

    if (offset >= total_size) {
        return 0;  /* EOF - nothing to write */
    }

    /* Calculate how many bytes to copy */
    if (offset + count > total_size) {
        bytes_to_copy = total_size - offset;
    } else {
        bytes_to_copy = count;
    }

    /* Copy pixel data to screen */
    memcpy(pixel_data + offset, buf, bytes_to_copy);

    /* Dump first 100 bytes on first write - disabled for cleaner output
    if (first_write && offset == 0) {
        int i;
        int dump_bytes = (count < 100) ? count : 100;
        fprintf(stderr, "devscreen_write: First %d bytes received: ", dump_bytes);
        for (i = 0; i < dump_bytes; i++) {
            fprintf(stderr, "%02X ", (unsigned char)buf[i]);
        }
        fprintf(stderr, "\n");
        first_write = 0;
    }
    */

    /* Verbose logging disabled - uncomment for debugging
    fprintf(stderr, "devscreen_write: wrote %lu bytes to screen\n", (unsigned long)bytes_to_copy);
    */

    return bytes_to_copy;
}

/*
 * Read from /dev/screen/ctl
 * Returns screen dimensions: "WIDTHxHEIGHT\n"
 */
static ssize_t devscreen_ctl_read(char *buf, size_t count, uint64_t offset,
                                  void *data)
{
    ScreenState *state = (ScreenState *)data;
    char size_str[64];
    int len;

    if (state == NULL || state->screen == NULL) {
        return 0;
    }

    /* Format: "WIDTHxHEIGHT\n" */
    len = snprint(size_str, sizeof(size_str), "%dx%d\n",
                  Dx(state->screen->r), Dy(state->screen->r));

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
    }

    memcpy(buf, size_str + offset, count);
    return (ssize_t)count;
}

/*
 * Write to /dev/screen/ctl
 * Accepts commands to resize the screen: "screen WIDTHxHEIGHT\n"
 * This allows the window manager to dynamically change the screen size.
 */
static ssize_t devscreen_ctl_write(const char *buf, size_t count, uint64_t offset,
                                   void *data)
{
    ScreenState *state = (ScreenState *)data;
    char cmd[64];
    size_t cmd_len;
    int width, height;
    int parsed;
    Rectangle new_rect;
    size_t new_size;

    (void)offset;  /* Write commands don't use offset */

    if (state == NULL || state->screen == NULL) {
        return -1;
    }

    if (buf == NULL || count == 0) {
        return -1;
    }

    /* Limit command length */
    cmd_len = (count < sizeof(cmd) - 1) ? count : sizeof(cmd) - 1;
    memcpy(cmd, buf, cmd_len);
    cmd[cmd_len] = '\0';

    /* Parse "screen WIDTHxHEIGHT\n" format */
    parsed = sscanf(cmd, "screen %dx%d", &width, &height);
    if (parsed != 2) {
        fprintf(stderr, "devscreen_ctl_write: invalid command format '%s'\n", cmd);
        return -1;
    }

    /* Validate dimensions */
    if (width <= 0 || height <= 0 || width > 8192 || height > 8192) {
        fprintf(stderr, "devscreen_ctl_write: invalid dimensions %dx%d\n", width, height);
        return -1;
    }

    fprintf(stderr, "devscreen_ctl_write: resizing screen to %dx%d\n", width, height);

    /* Update screen rectangle dimensions */
    new_rect.min.x = 0;
    new_rect.min.y = 0;
    new_rect.max.x = width;
    new_rect.max.y = height;
    state->screen->r = new_rect;

    /* Update file size in /dev/screen/data node */
    new_size = (size_t)width * (size_t)height * 4;
    if (g_screen_data_node != NULL) {
        g_screen_data_node->length = new_size;
        fprintf(stderr, "devscreen_ctl_write: updated file size to %lu bytes\n",
                (unsigned long)new_size);
    } else {
        fprintf(stderr, "devscreen_ctl_write: warning - no data node to update\n");
    }

    return (ssize_t)count;
}

/*
 * Initialize /dev/screen device
 */
int devscreen_init(P9Node *dev_dir, Memimage *screen)
{
    P9Node *screen_dir;
    P9Node *data_node;
    P9Node *ctl_node;
    ScreenState *state;

    if (dev_dir == NULL || screen == NULL) {
        return -1;
    }

    /* Allocate state */
    state = (ScreenState *)malloc(sizeof(ScreenState));
    if (state == NULL) {
        fprintf(stderr, "devscreen_init: cannot allocate state\n");
        return -1;
    }

    state->screen = screen;
    g_screen_state = state;

    /* Create /dev/screen directory */
    screen_dir = tree_create_dir(dev_dir, "screen");
    if (screen_dir == NULL) {
        fprintf(stderr, "devscreen_init: cannot create screen directory\n");
        free(state);
        return -1;
    }

    /* Create /dev/screen/data file */
    data_node = tree_create_file(screen_dir, "data",
                                 state,
                                 (P9ReadFunc)devscreen_read,
                                 (P9WriteFunc)devscreen_write);
    if (data_node == NULL) {
        fprintf(stderr, "devscreen_init: cannot create data node\n");
        free(state);
        return -1;
    }

    /* Store data node reference globally for resizing */
    g_screen_data_node = data_node;

    /* Set file size */
    data_node->length = Dx(screen->r) * Dy(screen->r) * 4;

    /* Create /dev/screen/ctl file */
    ctl_node = tree_create_file(screen_dir, "ctl",
                                state,
                                (P9ReadFunc)devscreen_ctl_read,
                                (P9WriteFunc)devscreen_ctl_write);
    if (ctl_node == NULL) {
        fprintf(stderr, "devscreen_init: cannot create ctl node\n");
        free(state);
        return -1;
    }

    fprintf(stderr, "devscreen_init: /dev/screen/data and /dev/screen/ctl ready\n");

    return 0;
}

/*
 * Get global screen state (for other devices)
 */
ScreenState *devscreen_get_state(void)
{
    return g_screen_state;
}

/*
 * Get screen image (for devdraw and other devices)
 */
Memimage *devscreen_get_screen(void)
{
    if (g_screen_state == NULL) {
        return NULL;
    }
    return g_screen_state->screen;
}

/*
 * Update screen reference (e.g., if screen is resized)
 */
int devscreen_set_screen(Memimage *screen)
{
    if (g_screen_state == NULL) {
        return -1;
    }

    g_screen_state->screen = screen;
    return 0;
}

/*
 * Cleanup screen device
 */
void devscreen_cleanup(void)
{
    if (g_screen_state != NULL) {
        /* Don't free the screen itself - it's owned by main.c */
        free(g_screen_state);
        g_screen_state = NULL;
    }
}
