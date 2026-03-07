/*
 * Marrow /dev/rendezvous Device
 * C89/C90 compliant
 *
 * Implements Plan 9 rendezvous and semaphore synchronization primitives
 * as a device, isolating Linux-specific futex and sys/syscall.h from
 * the Plan 9 syscall gateway (runtime/syscall.c).
 *
 * Rendezvous uses pthread_mutex + pthread_cond for portability.
 * Semaphore primitives (semacquire/semrelease) keep futex for efficiency
 * since they must operate on arbitrary caller-supplied addresses.
 */

#define _GNU_SOURCE  /* for syscall(), struct timespec, pthread */
#include "lib9p.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* Futex constants — kept here, not in syscall.c */
#ifndef FUTEX_WAIT
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#endif

#define REND_SIZE 32

typedef struct {
    volatile uint64_t tag;
    volatile uint64_t val;
    volatile int      done;    /* set by second caller when rendezvous completes */
    volatile int      active;
    pthread_cond_t    cond;
} RendSlot;

static RendSlot        g_slots[REND_SIZE];
static pthread_mutex_t g_mutex;
static int             g_initialized = 0;

/*
 * Initialize the rendezvous device.
 * dev_dir may be NULL (called before tree is ready); device still works.
 */
int devrendezvous_init(P9Node *dev_dir)
{
    int i;

    pthread_mutex_init(&g_mutex, NULL);

    for (i = 0; i < REND_SIZE; i++) {
        g_slots[i].active = 0;
        g_slots[i].done   = 0;
        pthread_cond_init(&g_slots[i].cond, NULL);
    }

    g_initialized = 1;

    if (dev_dir != NULL) {
        /* Expose /dev/rendezvous as a placeholder for future 9P-based access */
        tree_create_file(dev_dir, "rendezvous", NULL, NULL, NULL);
    }

    fprintf(stderr, "devrendezvous_init: initialized\n");
    return 0;
}

/*
 * Plan 9 rendezvous(2): two threads meet at tag, exchange values.
 *
 * First caller blocks until a second caller arrives with the same tag.
 * Second caller wakes the first and both return with the partner's value.
 *
 * Returns the partner's value on success, -1 on error (table full or
 * device not initialized).
 */
int64_t devrendezvous_call(uint64_t tag, uint64_t val)
{
    int i;
    uint64_t their_val;

    if (!g_initialized) {
        return -1;
    }

    pthread_mutex_lock(&g_mutex);

    /* Search for an existing waiter with the same tag */
    for (i = 0; i < REND_SIZE; i++) {
        if (g_slots[i].active && g_slots[i].tag == tag) {
            /* Found a match — complete the rendezvous */
            their_val        = g_slots[i].val;
            g_slots[i].val   = val;
            g_slots[i].done  = 1;
            pthread_cond_signal(&g_slots[i].cond);
            pthread_mutex_unlock(&g_mutex);
            return (int64_t)their_val;
        }
    }

    /* No waiter yet — become the first caller and block */
    for (i = 0; i < REND_SIZE; i++) {
        if (!g_slots[i].active) {
            g_slots[i].tag    = tag;
            g_slots[i].val    = val;
            g_slots[i].active = 1;
            g_slots[i].done   = 0;

            while (!g_slots[i].done) {
                pthread_cond_wait(&g_slots[i].cond, &g_mutex);
            }

            their_val         = g_slots[i].val;
            g_slots[i].active = 0;
            pthread_mutex_unlock(&g_mutex);
            return (int64_t)their_val;
        }
    }

    pthread_mutex_unlock(&g_mutex);
    return -1; /* rendezvous table full */
}

/*
 * Semaphore acquire: atomically decrement *addr if > 0, else block.
 * Uses futex for efficient in-kernel waiting on the shared integer.
 *
 * block == 0: non-blocking (returns -1 if addr == 0).
 * block == 1: blocking until addr > 0.
 */
int64_t devrendezvous_semacquire(int *addr, int block)
{
    int val;

    for (;;) {
        val = __atomic_load_n(addr, __ATOMIC_SEQ_CST);
        if (val > 0) {
            if (__atomic_compare_exchange_n(addr, &val, val - 1, 0,
                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                return 0;
            }
            /* CAS failed — retry */
            continue;
        }
        if (!block) {
            return -1;
        }
        /* Block until a release increments addr */
        syscall(SYS_futex, addr, FUTEX_WAIT, 0, NULL, NULL, 0);
    }
}

/*
 * Semaphore release: increment *addr by count and wake blocked acquirers.
 */
int64_t devrendezvous_semrelease(int *addr, int count)
{
    __atomic_add_fetch(addr, count, __ATOMIC_SEQ_CST);
    syscall(SYS_futex, addr, FUTEX_WAKE, count, NULL, NULL, 0);
    return (int64_t)count;
}

/*
 * Timed semaphore acquire with a millisecond timeout.
 * Returns 0 on success, -1 on timeout.
 */
int64_t devrendezvous_tsemacquire(int *addr, uint32_t ms)
{
    int val;
    struct timespec ts;
    long rc;

    ts.tv_sec  = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);

    for (;;) {
        val = __atomic_load_n(addr, __ATOMIC_SEQ_CST);
        if (val > 0) {
            if (__atomic_compare_exchange_n(addr, &val, val - 1, 0,
                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                return 0;
            }
            continue;
        }
        rc = syscall(SYS_futex, addr, FUTEX_WAIT, 0, &ts, NULL, 0);
        if (rc == -1 && errno == ETIMEDOUT) {
            return -1;
        }
    }
}
