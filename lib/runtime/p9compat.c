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
