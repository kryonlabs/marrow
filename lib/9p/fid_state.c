/*
 * FID State Management Implementation
 * TaijiOS - Per-FID State Management System
 *
 * Implementation of FID state management for streaming devices.
 */

#include "fid_state.h"
#include "lib9p.h"
#include <lib9.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * FID state hash table
 * Uses separate chaining for collision resolution
 */
#define FID_STATE_HASH_SIZE 256

static FIDState *fid_state_table[FID_STATE_HASH_SIZE];
static int fid_state_table_initialized = 0;

/*
 * Hash function for (client_fd, fid) pair
 */
static int fid_state_hash(uint32_t fid, int client_fd)
{
    return (fid ^ client_fd) % FID_STATE_HASH_SIZE;
}

/*
 * Initialize FID state table
 */
int fid_state_init(void)
{
    if (!fid_state_table_initialized) {
        memset(fid_state_table, 0, sizeof(fid_state_table));
        fid_state_table_initialized = 1;
        /* fprintf(stderr, "[FID_STATE] Initialized hash table (size=%d)\n",
                FID_STATE_HASH_SIZE); */
    }
    return 0;
}

/*
 * Create FID state
 */
FIDState *fid_state_create(uint32_t fid, int client_fd, P9Node *node)
{
    FIDState *state;
    int index;

    fid_state_init();

    state = (FIDState *)malloc(sizeof(FIDState));
    if (state == NULL) {
        /* fprintf(stderr, "[FID_STATE] Out of memory allocating FIDState\n"); */
        return NULL;
    }

    memset(state, 0, sizeof(FIDState));
    state->fid = fid;
    state->client_fd = client_fd;
    state->node = node;
    state->device_state = NULL;
    state->device_state_destroy = NULL;
    state->is_stream = 0;
    state->offset = 0;
    state->refcount = 1;
    state->is_open = 0;
    state->mode = 0;

    /* Add to hash table */
    index = fid_state_hash(fid, client_fd);
    state->next = fid_state_table[index];
    fid_state_table[index] = state;

    /* fprintf(stderr, "[FID_STATE] Created state for fid=%u client_fd=%d\n",
            fid, client_fd); */

    return state;
}

/*
 * Lookup FID state
 */
FIDState *fid_state_lookup(int client_fd, uint32_t fid_num)
{
    int index;
    FIDState *state;

    if (!fid_state_table_initialized) {
        return NULL;
    }

    index = fid_state_hash(fid_num, client_fd);
    state = fid_state_table[index];

    while (state != NULL) {
        if (state->fid == fid_num && state->client_fd == client_fd) {
            return state;
        }
        state = state->next;
    }

    return NULL;
}

/*
 * Destroy FID state
 */
void fid_state_destroy(FIDState *state)
{
    int index;
    FIDState **ptr;

    if (state == NULL) {
        return;
    }

    /* fprintf(stderr, "[FID_STATE] Destroying state for fid=%u client_fd=%d\n",
            state->fid, state->client_fd); */

    /* Remove from hash table */
    index = fid_state_hash(state->fid, state->client_fd);
    ptr = &fid_state_table[index];

    while (*ptr != NULL) {
        if (*ptr == state) {
            *ptr = state->next;
            break;
        }
        ptr = &((*ptr)->next);
    }

    /* Free device-specific state if present */
    if (state->device_state != NULL && state->device_state_destroy != NULL) {
        /* fprintf(stderr, "[FID_STATE] Freeing device state for fid=%u\n",
                state->fid); */
        state->device_state_destroy(state->device_state);
    }

    free(state);
}

/*
 * Device state management
 */
void *fid_state_get_device(FIDState *state)
{
    return state ? state->device_state : NULL;
}

void fid_state_set_device(FIDState *state, void *device_state,
                         void (*destroy_fn)(void*))
{
    if (state) {
        state->device_state = device_state;
        state->device_state_destroy = destroy_fn;
    }
}

/*
 * Stream flag
 */
int fid_state_is_stream(FIDState *state)
{
    return state ? state->is_stream : 0;
}

void fid_state_set_stream(FIDState *state, int is_stream)
{
    if (state) {
        state->is_stream = is_stream;
    }
}

/*
 * Offset management
 */
uint64_t fid_state_get_offset(FIDState *state)
{
    return state ? state->offset : 0;
}

void fid_state_set_offset(FIDState *state, uint64_t offset)
{
    if (state) {
        state->offset = offset;
    }
}

/*
 * Read position
 */
size_t fid_state_get_read_pos(FIDState *state)
{
    return state ? 0 : 0; /* Not stored in FIDState, stored in device-specific state */
}

void fid_state_set_read_pos(FIDState *state, size_t pos)
{
    /* Not stored in FIDState, stored in device-specific state */
    (void)state;
    (void)pos;
}

/*
 * Check if node is a streaming device
 */
int is_streaming_device(P9Node *node)
{
    char path[P9_MAX_STR];

    if (node == NULL) {
        return 0;
    }

    if (node_get_path(node, path, sizeof(path)) < 0) {
        return 0;
    }

    /* Check for known streaming devices */
    if (strcmp(path, "/dev/mouse") == 0 ||
        strcmp(path, "/dev/kbd") == 0 ||
        strcmp(path, "/dev/cons") == 0) {
        return 1;
    }

    return 0;
}

/*
 * Get full path for a node
 */
int node_get_path(P9Node *node, char *path, size_t path_size)
{
    P9Node *current;
    P9Node *stack[P9_MAX_STR];
    int depth = 0;
    int i;
    size_t len;
    char *p;

    if (node == NULL || path == NULL || path_size < 2) {
        return -1;
    }

    /* Build path from node to root */
    current = node;
    while (current != NULL && current != current->parent) {
        if (depth >= P9_MAX_STR - 1) {
            return -1;  /* Path too deep */
        }
        stack[depth++] = current;
        current = current->parent;
    }

    /* Build path string */
    p = path;
    len = path_size;

    /* Start with root */
    if (len < 2) {
        return -1;
    }
    *p++ = '/';
    len--;
    *p = '\0';

    /* Add components from root to node */
    for (i = depth - 1; i >= 0; i--) {
        size_t component_len;

        if (stack[i]->name == NULL) {
            continue;
        }

        component_len = strlen(stack[i]->name);

        /* Check if we need separator */
        if (p > path && p[-1] != '/') {
            if (len < 1) {
                return -1;
            }
            *p++ = '/';
            len--;
        }

        /* Check space for component */
        if (len < component_len + 1) {
            return -1;
        }

        strecpy(p, p + component_len + 1, stack[i]->name);
        p += component_len;
        len -= component_len;
    }

    *p = '\0';
    return 0;
}

/*
 * Cleanup FID states
 */
void fid_state_cleanup(int client_fd)
{
    int i;
    FIDState *state;
    FIDState *next;
    int count = 0;

    if (!fid_state_table_initialized) {
        return;
    }

    for (i = 0; i < FID_STATE_HASH_SIZE; i++) {
        state = fid_state_table[i];
        while (state != NULL) {
            next = state->next;

            if (client_fd == -1 || state->client_fd == client_fd) {
                fid_state_destroy(state);
                count++;
            }

            state = next;
        }
    }

    /* fprintf(stderr, "[FID_STATE] Cleaned up %d FID states (client_fd=%d)\n",
            count, client_fd); */
}
