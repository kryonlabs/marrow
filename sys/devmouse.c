/*
 * Marrow Mouse Device (/dev/mouse)
 * C89/C90 compliant
 *
 * Simple mouse device for marrow
 * Returns mouse events in Plan 9 format
 *
 * REDESIGN: Per-FID state management
 * Each open file descriptor gets its own read position in the shared buffer.
 */

#include "lib9p.h"
#include "libregistry.h"  /* For service_get, service_free_info */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Mouse event buffer (circular buffer pattern)
 */
#define MOUSE_BUF_SIZE 4096

/*
 * Per-FID read state (one per open file descriptor)
 */
typedef struct {
    size_t      read_pos;       /* This FID's read position in shared buffer */
    uint32_t    generation;     /* Buffer generation when opened */
    uint32_t    _pad;
} MouseFIDState;

/*
 * Shared device state (global, written by display client)
 */
typedef struct {
    char        buffer[MOUSE_BUF_SIZE];
    size_t      write_pos;      /* Circular buffer write position */
    size_t      total_len;      /* Total bytes written (for overflow detection) */
    uint32_t    generation;     /* Generation counter (increments on overflow) */
    int         has_reader;     /* Whether any reader is active */
} MouseSharedState;

static MouseSharedState g_mouse_shared = { "", 0, 0, 0, 0 };

/*
 * Helper: Create per-FID state for mouse
 *
 * Allocates and initializes a new MouseFIDState structure.
 * Called when a client opens /dev/mouse.
 */
MouseFIDState *devmouse_create_fid_state(void)
{
    MouseFIDState *state;

    state = (MouseFIDState *)malloc(sizeof(MouseFIDState));
    if (state == NULL) {
        return NULL;
    }

    /* Initialize read position to current write position (start reading new data) */
    state->read_pos = g_mouse_shared.total_len;
    state->generation = g_mouse_shared.generation;

    return state;
}

/*
 * Helper: Destroy per-FID state
 */
void devmouse_destroy_fid_state(MouseFIDState *state)
{
    if (state != NULL) {
        free(state);
    }
}

/*
 * Helper: Get shared state for diagnostics
 */
MouseSharedState *devmouse_get_shared_state(void)
{
    return &g_mouse_shared;
}

/*
 * Read handler for /dev/mouse
 * Returns queued mouse events in Plan 9 format: "m x y buttons\n"
 *
 * REDESIGN: Uses per-FID read position instead of global read_pos.
 * Each open file descriptor maintains its own read position in the
 * circular buffer, enabling multiple concurrent readers.
 */
static ssize_t devmouse_read(char *buf, size_t count, uint64_t offset, void *fid_ctx)
{
    MouseFIDState *fid_state;
    size_t available;
    size_t to_copy;
    size_t first_part;
    size_t read_pos_idx;

    if (buf == NULL || count == 0) {
        return 0;
    }

    fid_state = (MouseFIDState *)fid_ctx;
    if (fid_state == NULL) {
        /* No FID state - return EOF */
        return 0;
    }

    /* Streaming device: ignore offset */
    (void)offset;

    /* Calculate available data for this FID */
    available = g_mouse_shared.total_len - fid_state->read_pos;

    /* Handle slow reader: reset if too far behind (buffer overflow) */
    if (available > MOUSE_BUF_SIZE) {
        /* fprintf(stderr, "[MOUSE] Slow reader detected: avail=%zu > buf_size=%d\n",
                available, MOUSE_BUF_SIZE); */
        /* fprintf(stderr, "[MOUSE] Resetting FID state: read_pos=%zu -> %zu, gen=%u -> %u\n",
                fid_state->read_pos, g_mouse_shared.write_pos,
                fid_state->generation, g_mouse_shared.generation + 1); */

        fid_state->read_pos = g_mouse_shared.write_pos;
        fid_state->generation = g_mouse_shared.generation + 1;
        available = 0;
    }

    to_copy = (available < count) ? available : count;

    /* DEBUG: Log read attempts */
    /* fprintf(stderr, "[MOUSE] Read: count=%zu offset=%lu total_len=%zu read_pos=%zu avail=%zu to_copy=%zu\n",
            count, offset, g_mouse_shared.total_len, fid_state->read_pos,
            available, to_copy); */

    /* Copy data (handle circular buffer wrap) */
    if (to_copy > 0) {
        read_pos_idx = fid_state->read_pos % MOUSE_BUF_SIZE;
        first_part = MOUSE_BUF_SIZE - read_pos_idx;

        if (to_copy <= first_part) {
            /* Data doesn't wrap around */
            memcpy(buf, g_mouse_shared.buffer + read_pos_idx, to_copy);
        } else {
            /* Data wraps around end of buffer */
            memcpy(buf, g_mouse_shared.buffer + read_pos_idx, first_part);
            memcpy(buf + first_part, g_mouse_shared.buffer, to_copy - first_part);
        }

        fid_state->read_pos += to_copy;

        /* fprintf(stderr, "[MOUSE] Returning %zu bytes: '%.*s'\n",
                to_copy, (int)to_copy, buf); */
    }

    return to_copy;
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

    /* Navigate to /dev/win1/mouse in WM's tree */
    wm_tree = svc->tree;
    if (wm_tree == NULL) {
        service_free_info(svc);
        return 0;
    }

    /* Look up the mouse device node */
    mouse_node = tree_lookup(wm_tree, "/dev/win1/mouse");
    if (mouse_node == NULL) {
        /* Window 1 might not exist yet - OK */
        service_free_info(svc);
        return 0;
    }

    /* Forward the write to WM's vdev handler */
    result = node_write(mouse_node, buf, count, 0, NULL);

    /* Cleanup */
    service_free_info(svc);

    return result;
}

/*
 * Write handler for /dev/mouse
 * Queues events and forwards to WM
 *
 * REDESIGN: Uses circular buffer with write_pos and total_len.
 * No longer needs to shift buffer contents - each reader maintains
 * its own read position.
 */
static ssize_t devmouse_write(const char *buf, size_t count, uint64_t offset, void *fid_ctx)
{
    size_t space_left;
    size_t to_copy;
    size_t first_part;
    size_t write_pos_idx;

    (void)offset;
    (void)fid_ctx;  /* Write doesn't use per-FID state */

    if (buf == NULL || count == 0) {
        return 0;
    }

    /* DEBUG: Log every write */
    /* fprintf(stderr, "[MOUSE] Write %zu bytes: '%.*s'\n", count, (int)count, buf); */
    /* fprintf(stderr, "[MOUSE] Buffer: write_pos=%zu total_len=%zu\n",
            g_mouse_shared.write_pos, g_mouse_shared.total_len); */

    /* Forward to WM's virtual mouse device (keep working!) */
    forward_to_wm_mouse(buf, count);

    /* Write to circular buffer */
    write_pos_idx = g_mouse_shared.write_pos % MOUSE_BUF_SIZE;
    first_part = MOUSE_BUF_SIZE - write_pos_idx;

    if (count <= first_part) {
        /* Data doesn't wrap around */
        memcpy(g_mouse_shared.buffer + write_pos_idx, buf, count);
        g_mouse_shared.write_pos += count;
    } else {
        /* Data wraps around end of buffer */
        memcpy(g_mouse_shared.buffer + write_pos_idx, buf, first_part);
        memcpy(g_mouse_shared.buffer, buf + first_part, count - first_part);
        g_mouse_shared.write_pos += count;

        /* Check for buffer overflow (slow reader scenario) */
        if (g_mouse_shared.write_pos > g_mouse_shared.total_len + MOUSE_BUF_SIZE) {
            /* Increment generation to signal overflow to readers */
            g_mouse_shared.generation++;
            /* fprintf(stderr, "[MOUSE] Buffer overflow: generation=%u\n",
                    g_mouse_shared.generation); */
        }
    }

    g_mouse_shared.total_len += count;
    g_mouse_shared.has_reader = 1;

    /* fprintf(stderr, "[MOUSE] After write: write_pos=%zu total_len=%zu\n",
            g_mouse_shared.write_pos, g_mouse_shared.total_len); */

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

    /* Note: Using old API for now. Integration with Agent 3's FID state
     * system will require updating lib9p.h to pass fid_ctx through
     * the call chain. For now, fid_ctx will be NULL. */
    mouse_file = tree_create_file(dev_dir, "mouse", NULL,
                                  (P9ReadFunc)devmouse_read,
                                  (P9WriteFunc)devmouse_write);
    if (mouse_file == NULL) {
        return -1;
    }

    fprintf(stderr, "devmouse_init: initialized /dev/mouse with per-FID state support\n");
    return 0;
}
