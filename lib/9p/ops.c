/*
 * 9P FID Management Functions
 * Operation handlers have been moved to handlers.c (updated to use lib9)
 */

#include "lib9p.h"
#include "fid_state.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Current client fd (for CPU server tracking)
 * This is set before handling each message
 */
static int current_client_fd = -1;

/*
 * Set current client fd (called from server loop)
 */
void p9_set_client_fd(int fd)
{
    /* Verbose logging disabled - uncomment for debugging
    fprintf(stderr, "p9_set_client_fd: setting current_client_fd from %d to %d\n",
            current_client_fd, fd);
    */
    current_client_fd = fd;
}

/*
 * Get current client fd
 */
int p9_get_client_fd(void)
{
    return current_client_fd;
}


/*
 * FID table
 */
static P9Fid fid_table[P9_MAX_FID];
static int fid_table_initialized = 0;
static uint32_t negotiated_msize = P9_MAX_MSG;

/*
 * Initialize FID table
 */
int fid_init(void)
{
    int i;
    if (fid_table_initialized) return 0;

    for (i = 0; i < P9_MAX_FID; i++) {
        fid_table[i].fid = 0;
        fid_table[i].node = NULL;
        fid_table[i].client_fd = -1; /* -1 indicates slot is empty */
        fid_table[i].is_open = 0;
        fid_table[i].mode = 0;
        fid_table[i].fid_state = NULL;  /* Initialize FID state */
    }

    /* Initialize FID state subsystem */
    fid_state_init();

    fid_table_initialized = 1;
    return 0;
}

/**
 * Cleanup FIDs for a specific client
 */
void fid_cleanup_conn(int client_fd)
{
    int i;
    int cleared = 0;
    for (i = 0; i < P9_MAX_FID; i++) {
        if (fid_table[i].node != NULL && fid_table[i].client_fd == client_fd) {
            /* Cleanup FID state */
            if (fid_table[i].fid_state != NULL) {
                fid_state_destroy(fid_table[i].fid_state);
                fid_table[i].fid_state = NULL;
            }
            fid_table[i].node = NULL;
            fid_table[i].client_fd = -1;
            fid_table[i].is_open = 0;
            cleared++;
        }
    }
    if (cleared > 0) {
        fprintf(stderr, "fid_cleanup: released %d FIDs for fd %d\n", cleared, client_fd);
    }
}

/*
 * Allocate a new FID
 * Uses linear search to support multiple clients with same FID numbers
 */
P9Fid *fid_new(uint32_t fid_num, P9Node *node)
{
    int i;
    int free_slot = -1;

    /* Search for existing FID for this client, or find a free slot */
    for (i = 0; i < P9_MAX_FID; i++) {
        if (fid_table[i].node == NULL) {
            /* Found a free slot */
            if (free_slot < 0) free_slot = i;
        } else if (fid_table[i].client_fd == current_client_fd &&
                   fid_table[i].fid == fid_num) {
            /* FID already in use by this client */
            fprintf(stderr, "fid_new: FID %u already in use for client_fd=%d\n",
                    fid_num, current_client_fd);
            return NULL;
        }
    }

    if (free_slot < 0) {
        fprintf(stderr, "fid_new: no free slots in FID table\n");
        return NULL;
    }

    /* Allocate in free slot */
    fid_table[free_slot].fid = fid_num;
    fid_table[free_slot].node = node;
    fid_table[free_slot].client_fd = current_client_fd;
    fid_table[free_slot].is_open = 0;
    fid_table[free_slot].mode = 0;
    fid_table[free_slot].fid_state = NULL;  /* Initialize FID state */

    return &fid_table[free_slot];
}

/*
 * Get an existing FID
 * Uses linear search to find (client_fd, fid_num) pair
 */
P9Fid *fid_get(uint32_t fid_num)
{
    int i;

    for (i = 0; i < P9_MAX_FID; i++) {
        if (fid_table[i].node != NULL &&
            fid_table[i].client_fd == current_client_fd &&
            fid_table[i].fid == fid_num) {
            return &fid_table[i];
        }
    }

    fprintf(stderr, "fid_get: FID %u not found for client_fd=%d\n",
            fid_num, current_client_fd);
    return NULL;
}

/*
 * Release a FID
 */
int fid_put(uint32_t fid_num)
{
    return fid_clunk(fid_num);
}

/*
 * Clunk a FID (close if open, then release)
 * Uses linear search to find (client_fd, fid_num) pair
 */
int fid_clunk(uint32_t fid_num)
{
    int i;

    for (i = 0; i < P9_MAX_FID; i++) {
        if (fid_table[i].node != NULL &&
            fid_table[i].client_fd == current_client_fd &&
            fid_table[i].fid == fid_num) {

            if (fid_table[i].is_open) {
                /* Note: fd field not used in current implementation */
                /* close(fid_table[i].fd); */
            }

            /* Cleanup FID state */
            if (fid_table[i].fid_state != NULL) {
                fprintf(stderr, "fid_clunk: Cleaning up FID state for fid=%u\n", fid_num);
                fid_state_destroy(fid_table[i].fid_state);
                fid_table[i].fid_state = NULL;
            }

            fid_table[i].node = NULL;
            fid_table[i].client_fd = -1;
            fid_table[i].is_open = 0;
            fid_table[i].mode = 0;

            return 0;
        }
    }

    fprintf(stderr, "fid_clunk: FID %u not found for client_fd=%d\n",
            fid_num, current_client_fd);
    return -1;
}

/*
 * NOTE: All 9P operation handlers have been moved to handlers.c
 * and updated to use lib9's convM2S() and convS2M() functions.
 *
 * This file now contains only FID management functions.
 */
