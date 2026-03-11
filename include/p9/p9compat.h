#ifndef P9_P9COMPAT_H
#define P9_P9COMPAT_H

/*
 * Plan 9 Compatibility Layer for Marrow
 *
 * This header provides type definitions and compatibility macros
 * to help Marrow work with 9front code patterns and Plan 9 binaries.
 */

#include <stddef.h>
#include <stdint.h>

/*
 * Plan 9 basic types (from 9front u.h)
 * NOTE: lib9.h now defines most of these, so we only define what's missing
 */
#ifndef uchar
typedef unsigned char uchar;
#endif
#ifndef ushort
typedef unsigned short ushort;
#endif
#ifndef uint
typedef unsigned int uint;
#endif
#ifndef ulong
typedef unsigned long ulong;
#endif
/* uvlong and vlong are now defined by lib9.h */

/*
 * 9front uses u64int, u32int, etc.
 * Note: These are defined by plan9port's u.h, so we don't redefine them here
 * to avoid type conflicts (long long vs long on different platforms)
 */

/*
 * Plan 9 nil pointer
 */
#ifndef nil
#define nil NULL
#endif

/*
 * Plan 9 uses 'USED' to mark intentionally unused variables
 */
#ifndef USED
#define USED(x) _unused_##x = (x)
#endif

/*
 * Plan 9 uses 'SET' for variables that are set but not read
 */
#ifndef SET
#define SET(x) ((void)(&(x)))
#endif

/*
 * Error handling
 * Plan 9 functions typically return -1 on error and set errstr
 */
extern char *_p9_errstr;

#define P9_ERR_MAX  128

/*
 * Get/set error string
 */
void p9_set_errstr(const char *fmt, ...);
const char *p9_get_errstr(void);

/*
 * Open modes (from Plan 9 fcall.h)
 */
#define P9_OREAD   0   /* Open for reading */
#define P9_OWRITE  1   /* Open for writing */
#define P9_ORDWR   2   /* Open for read/write */
#define P9_OEXEC   3   /* Open for execution */

#define P9_OTRUNC  16  /* Truncate file */
#define P9_OCEXEC  32  /* Close on exec */
#define P9_ORCLOSE 64  /* Remove on close */

#define P9_OEXCL   0x1000 /* Exclusive create */

/*
 * File permissions (from Plan 9 fcall.h)
 */
#define P9_DMREAD   0x4  /* Read permission */
#define P9_DMWRITE  0x2  /* Write permission */
#define P9_DMEXEC   0x1  /* Execute permission */

#define P9_DMDIR    0x80000000  /* Directory */
#define P9_DMAPPEND 0x40000000  /* Append only */
#define P9_DMEXCL   0x20000000  /* Exclusive use */
#define P9_DMTMP    0x10000000  /* Non-backed file */
#define P9_DMDEVICE 0x08000000  /* Device file */

/*
 * Seek whence values (from Plan 9 syscall.h)
 */
#define P9_SEEK_SET 0  /* Seek from beginning */
#define P9_SEEK_CUR 1  /* Seek from current position */
#define P9_SEEK_END 2  /* Seek from end */

/*
 * Process states (from 9front portdat.h)
 */
typedef enum {
    P9ProcDead = 0,
    P9ProcRunning,
    P9ProcReady,
    P9ProcWaking,
    P9ProcBroken,
    P9ProcStopping,
    P9ProcStopped,
    P9ProcRendez,
    P9ProcWaitdown,
} P9ProcState;

/*
 * Lock structure (simplified from 9front)
 */
typedef struct {
    int val;
} P9Lock;

/*
 * Lock functions
 */
void p9_lock_init(P9Lock *l);
void p9_lock(P9Lock *l);
void p9_unlock(P9Lock *l);
int p9_canlock(P9Lock *l);

/*
 * String operations
 */
#define p9_strlen strlen
#define p9_strcmp strcmp
#define p9_strncmp strncmp
#define p9_strcpy strcpy
#define p9_strncpy strncpy
#define p9_strchr strchr
#define p9_strrchr strrchr
#define p9_memcmp memcmp
#define p9_memcpy memcpy
#define p9_memmove memmove
#define p9_memset memset

/*
 * Memory allocation
 */
#define p9_malloc malloc
#define p9_free free
#define p9_calloc calloc

/*
 * Print functions
 */
#define p9_print fprintf
#define p9_snprintf snprintf
#define p9_vsnprintf vsnprintf

/*
 * Utility macros
 */
#define P9_NELEM(a) (sizeof(a)/sizeof((a)[0]))
#define P9_OFFSET_OF(type, member) offsetof(type, member)

#endif /* P9_P9COMPAT_H */
