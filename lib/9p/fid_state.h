/*
 * FID State Management API
 * TaijiOS - Per-FID State Management System
 *
 * This header defines the API for managing per-FID state in TaijiOS.
 * It enables streaming devices like /dev/mouse and /dev/kbd to have
 * independent read positions for each open file descriptor.
 */

#ifndef FID_STATE_H
#define FID_STATE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Forward declarations
 */
typedef struct P9Node P9Node;

/*
 * ============================================================================
 * DATA STRUCTURES
 * ============================================================================
 */

/*
 * FIDState - Per-FID state container
 *
 * This structure is allocated for each FID that needs per-open state
 * (typically streaming devices like /dev/mouse, /dev/kbd)
 *
 * Size: 64 bytes (fits in one cache line on most CPUs)
 */
typedef struct FIDState {
    /* Identification */
    uint32_t            fid;            /* 9P FID number */
    int                 client_fd;      /* Client socket fd */

    /* Node reference */
    P9Node              *node;          /* File node this FID points to */

    /* Stream vs Seekable */
    int                 is_stream;      /* 1 = streaming device, 0 = seekable file */
    uint64_t            offset;         /* Current offset (for seekable files) */

    /* Device-specific state */
    void                *device_state;  /* Per-FID device state (e.g., read_pos) */
    void                (*device_state_destroy)(void*);

    /* Hash table chaining */
    struct FIDState     *next;          /* Next entry in hash bucket */

    /* Reference counting (for future use) */
    int                 refcount;       /* Reference count (for sharing) */

    /* Lifecycle tracking */
    int                 is_open;        /* Whether Topen was called */
    uint8_t             mode;           /* Open mode (OREAD, OWRITE, ORDWR) */

    /* Padding for alignment */
    uint8_t             _pad[3];
} FIDState;

/*
 * ============================================================================
 * CORE API - FID STATE MANAGEMENT
 * ============================================================================
 */

/*
 * Create FID state for a FID
 *
 * Allocates and initializes a new FIDState structure for the given FID.
 * The state is inserted into the global hash table for fast lookup.
 *
 * Parameters:
 *   fid        - 9P FID number
 *   client_fd  - Client socket file descriptor
 *   node       - File node this FID points to
 *
 * Returns:
 *   FIDState*  - Pointer to new FIDState on success
 *   NULL       - On failure (out of memory, hash table full, etc.)
 */
FIDState *fid_state_create(uint32_t fid, int client_fd, P9Node *node);

/*
 * Destroy FID state and free associated resources
 *
 * Removes the FIDState from the hash table, frees any device-specific
 * state, and frees the FIDState structure itself.
 *
 * Parameters:
 *   state      - FIDState to destroy
 *
 * Note:
 *   This function is safe to call with state=NULL (no-op)
 */
void fid_state_destroy(FIDState *state);

/*
 * Lookup FID state by (client_fd, fid_num)
 *
 * Searches the global hash table for a FIDState matching the given
 * client_fd and fid_num pair.
 *
 * Parameters:
 *   client_fd  - Client socket file descriptor
 *   fid_num    - 9P FID number
 *
 * Returns:
 *   FIDState*  - Pointer to FIDState on success
 *   NULL       - If not found
 *
 * Performance:
 *   O(1) average case (hash table with separate chaining)
 */
FIDState *fid_state_lookup(int client_fd, uint32_t fid_num);

/*
 * ============================================================================
 * DEVICE STATE MANAGEMENT
 * ============================================================================
 */

/*
 * Set device-specific state for a FID
 *
 * Attaches device-specific state (e.g., MouseFIDState) to a FIDState.
 * The destroy_fn will be called when the FIDState is destroyed.
 *
 * Parameters:
 *   state          - FIDState to attach device state to
 *   device_state   - Device-specific state pointer
 *   destroy_fn     - Function to call when freeing device_state (can be NULL)
 */
void fid_state_set_device(FIDState *state, void *device_state,
                         void (*destroy_fn)(void*));

/*
 * Get device-specific state for a FID
 *
 * Retrieves the device-specific state attached to a FIDState.
 *
 * Parameters:
 *   state      - FIDState to get device state from
 *
 * Returns:
 *   void*      - Device state pointer (or NULL if not set)
 */
void *fid_state_get_device(FIDState *state);

/*
 * ============================================================================
 * STREAM FLAG MANAGEMENT
 * ============================================================================
 */

/*
 * Set stream flag for a FID
 *
 * Marks a FID as a streaming device. Streaming devices ignore the
 * offset parameter in read operations and maintain their own
 * read position in the shared buffer.
 *
 * Parameters:
 *   state      - FIDState to mark as streaming
 *   is_stream  - 1 for streaming device, 0 for seekable file
 */
void fid_state_set_stream(FIDState *state, int is_stream);

/*
 * Check if FID is a streaming device
 *
 * Parameters:
 *   state      - FIDState to check
 *
 * Returns:
 *   1          - If streaming device
 *   0          - If seekable file or state is NULL
 */
int fid_state_is_stream(FIDState *state);

/*
 * ============================================================================
 * OFFSET MANAGEMENT (FOR SEEKABLE FILES)
 * ============================================================================
 */

/*
 * Get current offset for seekable files
 *
 * Returns the current file offset for seekable files.
 * For streaming devices, this should always be 0.
 *
 * Parameters:
 *   state      - FIDState to get offset from
 *
 * Returns:
 *   uint64_t   - Current offset in bytes
 */
uint64_t fid_state_get_offset(FIDState *state);

/*
 * Set current offset for seekable files
 *
 * Sets the current file offset for seekable files.
 * For streaming devices, this has no effect.
 *
 * Parameters:
 *   state      - FIDState to set offset for
 *   offset     - New offset in bytes
 */
void fid_state_set_offset(FIDState *state, uint64_t offset);

/*
 * ============================================================================
 * READ POSITION MANAGEMENT (FOR STREAMING DEVICES)
 * ============================================================================
 */

/*
 * Get read position for streaming devices
 *
 * Returns the current read position in the shared buffer.
 * This is the position of the next byte to be read.
 *
 * Parameters:
 *   state      - FIDState to get read position from
 *
 * Returns:
 *   size_t     - Current read position
 */
size_t fid_state_get_read_pos(FIDState *state);

/*
 * Set read position for streaming devices
 *
 * Sets the current read position in the shared buffer.
 * This is typically called after reading data.
 *
 * Parameters:
 *   state      - FIDState to set read position for
 *   pos        - New read position
 */
void fid_state_set_read_pos(FIDState *state, size_t pos);

/*
 * ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================
 */

/*
 * Check if a node represents a streaming device
 *
 * Determines if a given node is a streaming device (ignores offset)
 * or a seekable file (uses offset).
 *
 * Parameters:
 *   node       - File node to check
 *
 * Returns:
 *   1          - If node is a streaming device
 *   0          - If node is a seekable file
 *
 * Streaming devices in TaijiOS:
 *   - /dev/mouse
 *   - /dev/kbd
 *   - /dev/cons
 */
int is_streaming_device(P9Node *node);

/*
 * Get full path for a node
 *
 * Builds the full path from root to the given node.
 *
 * Parameters:
 *   node       - File node
 *   path       - Buffer to store path (must be at least P9_MAX_STR bytes)
 *   path_size  - Size of path buffer
 *
 * Returns:
 *   0          - On success
 *   -1         - On failure (buffer too small, etc.)
 */
int node_get_path(P9Node *node, char *path, size_t path_size);

/*
 * Initialize the FID state subsystem
 *
 * Must be called once at server startup before any FID operations.
 *
 * Returns:
 *   0          - On success
 *   -1         - On failure
 */
int fid_state_init(void);

/*
 * Cleanup the FID state subsystem
 *
 * Should be called at server shutdown to free all remaining FID states.
 * Also called when a client disconnects to clean up that client's FIDs.
 *
 * Parameters:
 *   client_fd  - Client file descriptor (or -1 for all clients)
 */
void fid_state_cleanup(int client_fd);

#endif /* FID_STATE_H */
