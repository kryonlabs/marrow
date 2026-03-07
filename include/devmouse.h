/*
 * Marrow Mouse Device API
 * C89/C90 compliant
 *
 * Public API for /dev/mouse device
 * Defines structures and helper functions for per-FID state management
 */

#ifndef DEVMOUSE_H
#define DEVMOUSE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Constants
 */
#define MOUSE_BUF_SIZE 4096

/*
 * Forward declarations
 */
typedef struct P9Node P9Node;

/*
 * Per-FID read state (one per open file descriptor)
 *
 * Each FID reading /dev/mouse gets one of these structures
 * to track its independent read position in the shared buffer.
 */
typedef struct {
    size_t      read_pos;       /* This FID's read position in shared buffer */
    uint32_t    generation;     /* Buffer generation when opened */
    uint32_t    _pad;
} MouseFIDState;

/*
 * Shared device state (global, written by display client)
 *
 * Global state shared by all FIDs reading /dev/mouse.
 * Written by display client, read by multiple FIDs.
 */
typedef struct {
    char        buffer[MOUSE_BUF_SIZE];
    size_t      write_pos;      /* Current write position */
    size_t      total_len;      /* Total bytes written (for wrap detection) */
    uint32_t    generation;     /* Generation counter (increments on overflow) */
    int         has_reader;     /* Whether any reader is active */
} MouseSharedState;

/*
 * ============================================================================
 * DEVICE INITIALIZATION
 * ============================================================================
 */

/*
 * Initialize /dev/mouse device
 *
 * Creates the /dev/mouse node in the device directory.
 *
 * Parameters:
 *   dev_dir    - Parent directory (typically /dev)
 *
 * Returns:
 *   0          - On success
 *   -1         - On failure
 */
int devmouse_init(P9Node *dev_dir);

/*
 * ============================================================================
 * PER-FID STATE MANAGEMENT
 * ============================================================================
 */

/*
 * Create per-FID state for mouse
 *
 * Allocates and initializes a new MouseFIDState structure.
 * Called when a client opens /dev/mouse.
 *
 * Returns:
 *   MouseFIDState* - Pointer to new state on success
 *   NULL           - On failure (out of memory)
 */
MouseFIDState *devmouse_create_fid_state(void);

/*
 * Destroy per-FID state
 *
 * Frees a MouseFIDState structure created by devmouse_create_fid_state().
 * Called when a client closes /dev/mouse.
 *
 * Parameters:
 *   state      - MouseFIDState to free (safe to pass NULL)
 */
void devmouse_destroy_fid_state(MouseFIDState *state);

/*
 * Get shared state for diagnostics
 *
 * Returns pointer to the global MouseSharedState structure.
 * Useful for debugging and monitoring.
 *
 * Returns:
 *   MouseSharedState* - Pointer to shared state
 */
MouseSharedState *devmouse_get_shared_state(void);

/*
 * ============================================================================
 * DEVICE HANDLERS (for direct use if needed)
 * ============================================================================
 */

/*
 * Read handler for /dev/mouse
 *
 * Returns queued mouse events in Plan 9 format: "m x y buttons\n"
 * Uses per-FID read position for concurrent readers.
 *
 * Parameters:
 *   buf        - Output buffer
 *   count      - Maximum bytes to read
 *   offset     - File offset (ignored for streaming devices)
 *   fid_ctx    - Per-FID state (MouseFIDState*)
 *
 * Returns:
 *   ssize_t    - Number of bytes read (0 on EOF)
 */
ssize_t devmouse_read(char *buf, size_t count, uint64_t offset, void *fid_ctx);

/*
 * Write handler for /dev/mouse
 *
 * Queues mouse events and forwards to Kryon WM.
 * Uses circular buffer for concurrent readers.
 *
 * Parameters:
 *   buf        - Input buffer containing mouse events
 *   count      - Number of bytes to write
 *   offset     - File offset (ignored)
 *   fid_ctx    - Per-FID state (ignored for writes)
 *
 * Returns:
 *   ssize_t    - Number of bytes written
 */
ssize_t devmouse_write(const char *buf, size_t count, uint64_t offset, void *fid_ctx);

#endif /* DEVMOUSE_H */
