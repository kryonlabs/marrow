/*
 * Plan 9 Compatibility Layer Implementation for Marrow
 * C89/C90 compliant
 *
 * This provides utility functions and type compatibility
 * to help Marrow work with 9front code patterns.
 */

#include "runtime/syscall.h"
#include "p9/p9compat.h"
#include <lib9.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

/*
 * Error string storage
 * Plan 9 uses a single global error string that is set on error.
 */
static char _p9_errstr_buf[P9_ERR_MAX];

void
p9_set_errstr(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vsnprintf(_p9_errstr_buf, sizeof(_p9_errstr_buf), fmt, args);
    va_end(args);
}

const char *
p9_get_errstr(void)
{
    return _p9_errstr_buf;
}

/*
 * Lock functions (simplified for single-threaded operation)
 * TODO: Implement proper locking if Marrow becomes multi-threaded
 */

void
p9_lock_init(P9Lock *l)
{
    if (l != NULL) {
        l->val = 0;
    }
}

void
p9_lock(P9Lock *l)
{
    /* No-op for single-threaded */
    if (l != NULL) {
        l->val = 1;
    }
}

void
p9_unlock(P9Lock *l)
{
    /* No-op for single-threaded */
    if (l != NULL) {
        l->val = 0;
    }
}

int
p9_canlock(P9Lock *l)
{
    /* Always succeeds for single-threaded */
    if (l != NULL) {
        if (l->val == 0) {
            l->val = 1;
            return 1;
        }
        return 0;
    }
    return 1;
}

/*
 * Get CPU frequency for _tos support
 * Returns CPU frequency in Hz
 */
uint64_t
p9_cpufreq(void)
{
    FILE *f;
    uint64_t freq = 0;
    char line[256];

    /* Try reading from /sys/devices/system/cpu/cpu0/cpufreq/sc_cur_freq */
    f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/sc_cur_freq", "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            freq = (uint64_t)atoll(line) * 1000;  /* Convert kHz to Hz */
        }
        fclose(f);
    }

    /* Fallback: try base frequency */
    if (freq == 0) {
        f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/base_frequency", "r");
        if (f) {
            if (fgets(line, sizeof(line), f)) {
                freq = (uint64_t)atoll(line) * 1000;  /* Convert kHz to Hz */
            }
            fclose(f);
        }
    }

    /* Fallback: use CPUID to get max frequency (x86_64 only) */
#ifdef __x86_64__
    if (freq == 0) {
        unsigned int eax, ebx, ecx, edx;
        /* CPUID leaf 0x16 gives frequency info */
        __asm__ __volatile__("cpuid"
                             : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                             : "a"(0x16));
        if (eax != 0) {
            freq = ((uint64_t)ebx) * 1000000ULL;  /* Base frequency in MHz to Hz */
        }
    }
#endif

    /* Default: 2 GHz */
    if (freq == 0) {
        freq = 2000000000ULL;
    }

    return freq;
}

/*
 * Simple random number generator for RFREND tag
 */
uint32_t
p9_rand(void)
{
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    return (uint32_t)rand();
}
