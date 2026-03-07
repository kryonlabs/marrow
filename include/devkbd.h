/*
 * Marrow Keyboard Device API
 * C89/C90 compliant
 *
 * Public API for /dev/kbd device
 * Defines structures and helper functions for per-FID state management
 */

#ifndef DEVKBD_H
#define DEVKBD_H

#include <stddef.h>
#include <stdint.h>

/*
 * Constants
 */
#define KBD_BUF_SIZE 2048

/*
 * Forward declarations
 */
typedef struct P9Node P9Node;

/*
 * Per-FID read state (one per open file descriptor)
 *
 * Each FID reading /dev/kbd gets one of these structures
 * to track its independent read position in the shared buffer.
 */
typedef struct {
    size_t      read_pos;       /* This FID's read position in shared buffer */
    uint32_t    generation;     /* Buffer generation when opened */
    uint32_t    _pad;
} KbdFIDState;

/*
 * Shared device state (global, written by display client)
 *
 * Global state shared by all FIDs reading /dev/kbd.
 * Written by display client, read by multiple FIDs.
 */
typedef struct {
    char        buffer[KBD_BUF_SIZE];
    size_t      write_pos;      /* Current write position */
    size_t      total_len;      /* Total bytes written (for wrap detection) */
    uint32_t    generation;     /* Generation counter (increments on overflow) */
    int         has_reader;     /* Whether any reader is active */
} KbdSharedState;

/*
 * ============================================================================
 * DEVICE INITIALIZATION
 * ============================================================================
 */

/*
 * Initialize /dev/kbd device
 *
 * Creates the /dev/kbd node in the device directory.
 *
 * Parameters:
 *   dev_dir    - Parent directory (typically /dev)
 *
 * Returns:
 *   0          - On success
 *   -1         - On failure
 */
int devkbd_init(P9Node *dev_dir);

/*
 * ============================================================================
 * PER-FID STATE MANAGEMENT
 * ============================================================================
 */

/*
 * Create per-FID state for keyboard
 *
 * Allocates and initializes a new KbdFIDState structure.
 * Called when a client opens /dev/kbd.
 *
 * Returns:
 *   KbdFIDState* - Pointer to new state on success
 *   NULL         - On failure (out of memory)
 */
KbdFIDState *devkbd_create_fid_state(void);

/*
 * Destroy per-FID state
 *
 * Frees a KbdFIDState structure created by devkbd_create_fid_state().
 * Called when a client closes /dev/kbd.
 *
 * Parameters:
 *   state      - KbdFIDState to free (safe to pass NULL)
 */
void devkbd_destroy_fid_state(KbdFIDState *state);

/*
 * Get shared state for diagnostics
 *
 * Returns pointer to the global KbdSharedState structure.
 * Useful for debugging and monitoring.
 *
 * Returns:
 *   KbdSharedState* - Pointer to shared state
 */
KbdSharedState *devkbd_get_shared_state(void);

/*
 * ============================================================================
 * DEVICE HANDLERS (for direct use if needed)
 * ============================================================================
 */

/*
 * Read handler for /dev/kbd
 *
 * Returns queued keyboard events.
 * Uses per-FID read position for concurrent readers.
 *
 * Parameters:
 *   buf        - Output buffer
 *   count      - Maximum bytes to read
 *   offset     - File offset (ignored for streaming devices)
 *   fid_ctx    - Per-FID state (KbdFIDState*)
 *
 * Returns:
 *   ssize_t    - Number of bytes read (0 on EOF)
 */
ssize_t devkbd_read(char *buf, size_t count, uint64_t offset, void *fid_ctx);

/*
 * Write handler for /dev/kbd
 *
 * Queues keyboard events and forwards to Kryon WM.
 * Uses circular buffer for concurrent readers.
 *
 * Parameters:
 *   buf        - Input buffer containing keyboard events
 *   count      - Number of bytes to write
 *   offset     - File offset (ignored)
 *   fid_ctx    - Per-FID state (ignored for writes)
 *
 * Returns:
 *   ssize_t    - Number of bytes written
 */
ssize_t devkbd_write(const char *buf, size_t count, uint64_t offset, void *fid_ctx);

#endif /* DEVKBD_H */
