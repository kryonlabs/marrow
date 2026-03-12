#ifndef SYSCALL_H
#define SYSCALL_H

#include "runtime/peb.h"
#include <stdint.h>

/*
 * Plan 9 Syscall Gateway
 * C89/C90 compliant
 *
 * This module intercepts SYSCALL instructions from Plan 9 binaries
 * and routes them to Marrow's 9P implementation.
 */

/*
 * Plan 9 syscall numbers - 9front Compatible
 * Source: 9front sys/src/libc/9syscall/sys.h
 *
 * CRITICAL: These numbers MUST match 9front exactly for binary compatibility!
 * Do NOT change these numbers without understanding the implications.
 *
 * Note: Some syscalls have been deprecated over time.
 * Underscore prefix (_) indicates deprecated syscalls.
 */
#define P9_SYS_SYSR1       0      /* Reserved */
#define P9_SYS__ERRSTR     1      /* Error string (deprecated) */
#define P9_SYS_BIND        2      /* Bind a file descriptor to path */
#define P9_SYS_CHDIR       3      /* Change directory */
#define P9_SYS_CLOSE       4      /* Close file descriptor */
#define P9_SYS_DUP         5      /* Duplicate file descriptor */
#define P9_SYS_ALARM       6      /* Set alarm */
#define P9_SYS_EXEC        7      /* Execute a program */
#define P9_SYS_EXITS       8      /* Exit with status */
#define P9_SYS__FSESSION   9      /* Session (deprecated) */
#define P9_SYS_FAUTH      10      /* Authenticate file */
#define P9_SYS__FSTAT     11      /* Fstat (deprecated, use FSTAT=43) */
#define P9_SYS_SEGBRK     12      /* Segment break */
#define P9_SYS__MOUNT     13      /* Mount (deprecated, use MOUNT=46) */
#define P9_SYS_OPEN       14      /* Open file */
#define P9_SYS__READ      15      /* Read (deprecated, use PREAD=50) */
#define P9_SYS_OSEEK      16      /* Offset seek (deprecated, use SEEK=39) */
#define P9_SYS_SLEEP      17      /* Sleep */
#define P9_SYS__STAT      18      /* Stat (deprecated, use STAT=42) */
#define P9_SYS_RFORK      19      /* Fork process */
#define P9_SYS__WRITE     20      /* Write (deprecated, use PWRITE=51) */
#define P9_SYS_PIPE       21      /* Create pipe */
#define P9_SYS_CREATE     22      /* Create file */
#define P9_SYS_FD2PATH    23      /* Get path from fd */
#define P9_SYS_BRK_       24      /* Set break (memory) */
#define P9_SYS_REMOVE     25      /* Remove file */
#define P9_SYS__WSTAT     26      /* Wstat (deprecated, use WSTAT=44) */
#define P9_SYS__FWSTAT    27      /* FWstat (deprecated, use FWSTAT=45) */
#define P9_SYS_NOTIFY     28      /* Notify on file descriptor */
#define P9_SYS_NOTED      29      /* Send note */
#define P9_SYS_SEGATTACH  30      /* Attach segment */
#define P9_SYS_SEGDETACH  31      /* Detach segment */
#define P9_SYS_SEGFREE    32      /* Free segment */
#define P9_SYS_SEGFLUSH   33      /* Flush segment */
#define P9_SYS_RENDEZVOUS 34      /* Rendezvous point */
#define P9_SYS_UNMOUNT    35      /* Unmount */
#define P9_SYS__WAIT      36      /* Wait for child */
#define P9_SYS_SEMACQUIRE 37      /* Acquire semaphore */
#define P9_SYS_SEMRELEASE 38      /* Release semaphore */
#define P9_SYS_SEEK       39      /* Seek */
#define P9_SYS_FVERSION   40      /* Fid version */
#define P9_SYS_ERRSTR     41      /* Error string */
#define P9_SYS_STAT       42      /* Get file stats */
#define P9_SYS_FSTAT      43      /* Get fd stats */
#define P9_SYS_WSTAT      44      /* Write file stats */
#define P9_SYS_FWSTAT     45      /* Write fd stats */
#define P9_SYS_MOUNT      46      /* Mount */
#define P9_SYS_AWAIT      47      /* Await event */
#define P9_SYS_PREAD      50      /* Pread */
#define P9_SYS_PWRITE     51      /* Pwrite */
#define P9_SYS_TSEMACQUIRE 52     /* Acquire semaphore with timeout */
#define P9_SYS__NSEC      53      /* Nanoseconds */
#define P9_SYS_TOS        54      /* Get _tos pointer */

/*
 * Syscall gateway API
 */

/*
 * Initialize syscall gateway
 * Returns 0 on success, -1 on error
 */
int p9sys_init(void);

/*
 * Cleanup syscall gateway
 */
void p9sys_cleanup(void);

/*
 * Patch SYSCALL instructions in text segment
 *
 * Scans the text segment for SYSCALL opcodes (0F 05) and patches
 * them to CALL rel32 instructions that jump to the syscall gateway.
 *
 * Parameters:
 *   peb - PEB with loaded text segment
 *
 * Returns number of syscalls patched, or -1 on error
 */
int p9sys_patch_syscalls(PEB *peb);

/*
 * Syscall gateway handler
 *
 * Called from the assembly gateway stub when a patched SYSCALL is executed.
 *
 * Parameters:
 *   peb         - PEB for the current process
 *   syscall_num - Syscall number (from RAX)
 *   args        - Array of syscall arguments
 *
 * Returns the syscall return value
 */
int64_t p9sys_gateway(PEB *peb, int syscall_num, uint64_t *args);

/*
 * Syscall handlers for individual syscalls
 *
 * These implementations are based on 9front patterns but adapted
 * for Marrow's hosted environment.
 */

/* File I/O syscalls */
int64_t p9sys_open(PEB *peb, const char *path, int mode);
int64_t p9sys_pread(PEB *peb, int fd, void *buf, int count, int64_t offset);
int64_t p9sys_pwrite(PEB *peb, int fd, const void *buf, int count, int64_t offset);
int64_t p9sys_close(PEB *peb, int fd);
int64_t p9sys_create(PEB *peb, const char *path, int mode, uint32_t perm);
int64_t p9sys_remove(PEB *peb, const char *path);
int64_t p9sys_seek(PEB *peb, int fd, int64_t offset, int whence);

/* Directory syscalls */
int64_t p9sys_bind(PEB *peb, const char *path, const char *spec, int flags);
int64_t p9sys_mount(PEB *peb, int fd, const char *spec, int flags,
                   const char *aname);
int64_t p9sys_unmount(PEB *peb, const char *spec, const char *where);
int64_t p9sys_chdir(PEB *peb, const char *path);

/* Pipe syscall */
int64_t p9sys_pipe(PEB *peb, int *fds);

/* Process syscalls */
int64_t p9sys_exits(PEB *peb, const char *msg);
int64_t p9sys_brk(PEB *peb, void *addr);
int64_t p9sys_sleep(PEB *peb, int milliseconds);
int64_t p9sys_rfork(PEB *peb, int flags);
int64_t p9sys_exec(PEB *peb, const char *path, char **argv);
int64_t p9sys_alarm(PEB *peb, uint32_t ms);

/* File status syscalls */
int64_t p9sys_stat(PEB *peb, const char *path, uint8_t *buf, int nbuf);
int64_t p9sys_fstat(PEB *peb, int fd, uint8_t *buf, int nbuf);
int64_t p9sys_wstat(PEB *peb, const char *path, uint8_t *buf, int nbuf);
int64_t p9sys_fwstat(PEB *peb, int fd, uint8_t *buf, int nbuf);

/* FD operations */
int64_t p9sys_dup(PEB *peb, int fd, int newfd);
int64_t p9sys_fd2path(PEB *peb, int fd, char *buf, int nbuf);

/* Segment operations */
int64_t p9sys_segattach(PEB *peb, int type, const char *name,
                       void *addr, uint64_t len);
int64_t p9sys_segdetach(PEB *peb, void *addr);
int64_t p9sys_segfree(PEB *peb, void *addr, uint64_t len);
int64_t p9sys_segflush(PEB *peb, void *addr, uint64_t len);

/* Synchronization */
int64_t p9sys_rendezvous(PEB *peb, uint64_t tag, uint64_t val);
int64_t p9sys_semacquire(PEB *peb, int *addr, int block);
int64_t p9sys_semrelease(PEB *peb, int *addr, int count);
int64_t p9sys_tsemacquire(PEB *peb, int *addr, uint32_t ms);

/* Note (signal) system */
int64_t p9sys_notify(PEB *peb, void *fn);
int64_t p9sys_noted(PEB *peb, int v);
int64_t p9sys_await(PEB *peb, char *buf, int len);

/* Error string */
int64_t p9sys_errstr(PEB *peb, char *buf, int len);

/* Nanoseconds */
int64_t p9sys_nsec(PEB *peb);

/* _tos pointer */
int64_t p9sys_tos(PEB *peb);

/*
 * Assembly syscall gateway stub
 * Called from patched SYSCALL instructions
 *
 * Parameters:
 *   RAX = syscall number
 *   R15 = pointer to PEB
 *
 * Returns syscall result in RAX
 */
extern void p9sys_gateway_stub(void);

/*
 * Get the address of the syscall gateway for patching
 */
void *p9sys_get_gateway_addr(void);

#endif /* SYSCALL_H */
