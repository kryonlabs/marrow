/*
 * Plan 9 Syscall Gateway Implementation
 * C89/C90 compliant
 *
 * Intercepts SYSCALL instructions from Plan 9 binaries
 * and routes them to Marrow's 9P implementation.
 *
 * Based on 9front sys/src/9/port/sysfile.c patterns
 */

#include "runtime/syscall.h"
#include "lib9p.h"
#include "p9/p9compat.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

/* Futex constants (avoid depending on linux/futex.h) */
#ifndef FUTEX_WAIT
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#endif

/* Plan 9 pread/pwrite: offset == -1 means "use current position" */
#define P9_NOSEEK ((int64_t)-1LL)

/* Plan 9 rfork flags (9front libc.h) */
#define P9_RFNAMEG  (1<<0)
#define P9_RFENVG   (1<<1)
#define P9_RFFDG    (1<<2)
#define P9_RFNOTEG  (1<<3)
#define P9_RFPROC   (1<<4)
#define P9_RFMEM    (1<<5)
#define P9_RFNOWAIT (1<<6)

/* Rendezvous table */
#define P9_REND_SIZE 32

typedef struct {
    volatile uint64_t tag;
    volatile uint64_t val;
    volatile int      futex;
    volatile int      active;
} P9RendSlot;

static P9RendSlot g_rendtable[P9_REND_SIZE];
static volatile int g_rendlock = 0;

/*
 * Syscall gateway address (set at initialization)
 */
static void *g_gateway_addr = NULL;

/*
 * Initialize syscall gateway
 */
int p9sys_init(void)
{
    /* Set gateway address to the assembly stub */
    g_gateway_addr = (void *)p9sys_gateway_stub;

    if (g_gateway_addr == NULL) {
        fprintf(stderr, "p9sys_init: failed to get gateway address\n");
        return -1;
    }

    fprintf(stderr, "p9sys_init: initialized, gateway at %p\n", g_gateway_addr);

    return 0;
}

/*
 * Cleanup syscall gateway
 */
void p9sys_cleanup(void)
{
    g_gateway_addr = NULL;
}

/*
 * Get the address of the syscall gateway for patching
 */
void *p9sys_get_gateway_addr(void)
{
    return g_gateway_addr;
}

/*
 * Patch SYSCALL instructions in text segment
 */
int p9sys_patch_syscalls(PEB *peb)
{
    uint8_t *text;
    uint32_t text_size;
    uint32_t i;
    int count;
    void *gateway;

    if (peb == NULL) {
        fprintf(stderr, "p9sys_patch_syscalls: NULL peb\n");
        return -1;
    }

    text = peb->text.base;
    text_size = peb->text.size;
    gateway = g_gateway_addr;

    if (text == NULL) {
        fprintf(stderr, "p9sys_patch_syscalls: no text segment\n");
        return -1;
    }

    if (gateway == NULL) {
        fprintf(stderr, "p9sys_patch_syscalls: gateway not initialized\n");
        return -1;
    }

    count = 0;

    /* Scan for SYSCALL opcode (0F 05) */
    for (i = 0; i < text_size - 1; i++) {
        if (text[i] == 0x0F && text[i + 1] == 0x05) {
            /* Found SYSCALL instruction at offset i */

            /* Calculate relative offset to gateway */
            /* CALL rel32: E8 [4-byte relative offset] */
            /* The offset is from the instruction AFTER the CALL */
            int64_t rel_offset = (uint8_t *)gateway - (text + i + 5);

            /* Check if offset fits in 32 bits */
            if (rel_offset < -2147483648LL || rel_offset > 2147483647LL) {
                fprintf(stderr, "p9sys_patch_syscalls: gateway too far (offset=%lld)\n",
                        (long long)rel_offset);
                return -1;
            }

            /* Make text segment writable for patching */
            if (mprotect(text, text_size, PROT_READ | PROT_WRITE) < 0) {
                perror("p9sys_patch_syscalls: mprotect failed");
                return -1;
            }

            /* Patch: SYSCALL (2 bytes) -> CALL rel32 NOP (6 bytes) */
            text[i] = 0xE8;                        /* CALL rel32 */
            *(int32_t *)(text + i + 1) = (int32_t)rel_offset;
            text[i + 5] = 0x90;                    /* NOP */

            /* Restore RX protection */
            if (mprotect(text, text_size, PROT_READ | PROT_EXEC) < 0) {
                perror("p9sys_patch_syscalls: mprotect restore failed");
                return -1;
            }

            count++;

            fprintf(stderr, "p9sys_patch_syscalls: patched syscall at offset %u\n", i);

            /* Skip ahead */
            i += 1;
        }
    }

    fprintf(stderr, "p9sys_patch_syscalls: patched %d syscalls\n", count);

    return count;
}

/*
 * Syscall gateway handler
 * Called from the assembly gateway stub
 */
int64_t p9sys_gateway(PEB *peb, int syscall_num, uint64_t *args)
{
    int64_t result = 0;

    if (peb == NULL) {
        fprintf(stderr, "p9sys_gateway: NULL peb\n");
        return -1;
    }

    /* Dispatch to appropriate handler */
    switch (syscall_num) {
        /* File I/O */
        case P9_SYS_OPEN:
            result = p9sys_open(peb, (const char *)args[0], (int)args[1]);
            break;

        case P9_SYS_PREAD:
            result = p9sys_pread(peb, (int)args[0], (void *)args[1], (int)args[2]);
            break;

        case P9_SYS_PWRITE:
            result = p9sys_pwrite(peb, (int)args[0], (const void *)args[1], (int)args[2]);
            break;

        case P9_SYS_CLOSE:
            result = p9sys_close(peb, (int)args[0]);
            break;

        case P9_SYS_CREATE:
            result = p9sys_create(peb, (const char *)args[0], (int)args[1],
                                  (uint32_t)args[2]);
            break;

        case P9_SYS_REMOVE:
            result = p9sys_remove(peb, (const char *)args[0]);
            break;

        case P9_SYS_SEEK:
            result = p9sys_seek(peb, (int)args[0], (int64_t)args[1], (int)args[2]);
            break;

        /* Directory operations */
        case P9_SYS_BIND:
            result = p9sys_bind(peb, (const char *)args[0], (const char *)args[1],
                               (int)args[2]);
            break;

        case P9_SYS_UNMOUNT:
            result = p9sys_unmount(peb, (const char *)args[0], (const char *)args[1]);
            break;

        case P9_SYS_MOUNT:
            result = p9sys_mount(peb, (int)args[0], (const char *)args[1],
                                (int)args[2], (const char *)args[3]);
            break;

        /* Pipe */
        case P9_SYS_PIPE:
            result = p9sys_pipe(peb, (int *)args[0]);
            break;

        /* Process operations */
        case P9_SYS_EXITS:
            result = p9sys_exits(peb, (const char *)args[0]);
            break;

        case P9_SYS_BRK_:
            result = p9sys_brk(peb, (void *)args[0]);
            break;

        case P9_SYS_SLEEP:
            result = p9sys_sleep(peb, (int)args[0]);
            break;

        case P9_SYS_RFORK:
            result = p9sys_rfork(peb, (int)args[0]);
            break;

        /* FD operations */
        case P9_SYS_DUP:
            result = p9sys_dup(peb, (int)args[0], (int)args[1]);
            break;

        case P9_SYS_FD2PATH:
            result = p9sys_fd2path(peb, (int)args[0], (char *)args[1], (int)args[2]);
            break;

        /* File status */
        case P9_SYS_STAT:
            result = p9sys_stat(peb, (const char *)args[0], (uint8_t *)args[1],
                               (int)args[2]);
            break;

        case P9_SYS_FSTAT:
            result = p9sys_fstat(peb, (int)args[0], (uint8_t *)args[1],
                               (int)args[2]);
            break;

        case P9_SYS_WSTAT:
            result = p9sys_wstat(peb, (const char *)args[0], (uint8_t *)args[1],
                                (int)args[2]);
            break;

        case P9_SYS_FWSTAT:
            result = p9sys_fwstat(peb, (int)args[0], (uint8_t *)args[1],
                                 (int)args[2]);
            break;

        /* Segment operations */
        case P9_SYS_SEGATTACH:
            result = p9sys_segattach(peb, (int)args[0], (const char *)args[1],
                                    (void *)args[2], (uint64_t)args[3]);
            break;

        case P9_SYS_SEGDETACH:
            result = p9sys_segdetach(peb, (void *)args[0]);
            break;

        case P9_SYS_SEGFREE:
            result = p9sys_segfree(peb, (void *)args[0], (uint64_t)args[1]);
            break;

        case P9_SYS_SEGFLUSH:
            result = p9sys_segflush(peb, (void *)args[0], (uint64_t)args[1]);
            break;

        /* Synchronization */
        case P9_SYS_RENDEZVOUS:
            result = p9sys_rendezvous(peb, (uint64_t)args[0], (uint64_t)args[1]);
            break;

        default:
            fprintf(stderr, "p9sys_gateway: unimplemented syscall %d\n",
                    syscall_num);
            result = -1;
            break;
    }

    return result;
}

/*
 * Syscall: open
 * Based on 9front sysopen()
 */
int64_t p9sys_open(PEB *peb, const char *path, int mode)
{
    P9FdEntry *fd_entry;
    int fd;
    P9Node *root;
    P9Node *node;

    if (peb == NULL || path == NULL) {
        p9_set_errstr("open: invalid argument");
        return -1;
    }

    /* Validate open mode (based on 9front openmode()) */
    switch (mode & 0x3) {
        case P9_OREAD:
        case P9_OWRITE:
        case P9_ORDWR:
        case P9_OEXEC:
            break;
        default:
            p9_set_errstr("open: invalid mode");
            return -1;
    }

    /* Walk the 9P tree to find the file */
    root = tree_root();
    if (root == NULL) {
        p9_set_errstr("open: no root filesystem");
        return -1;
    }

    node = tree_walk(root, path);
    if (node == NULL) {
        p9_set_errstr("open: file not found");
        return -1;
    }

    /* Allocate a file descriptor */
    fd = peb_alloc_fd(peb);
    if (fd < 0) {
        p9_set_errstr("open: no free file descriptors");
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry != NULL) {
        fd_entry->is_active = 1;
        fd_entry->node_ptr = node;
        fd_entry->mode = mode;
        fd_entry->offset = 0;
    }

    fprintf(stderr, "p9sys_open: path=%s mode=%d -> fd=%d\n", path, mode, fd);

    return (int64_t)fd;
}

/*
 * Syscall: pread
 * Positional read
 */
int64_t p9sys_pread(PEB *peb, int fd, void *buf, int count)
{
    P9FdEntry *fd_entry;
    int64_t result;
    P9Node *node;
    uint64_t offset;

    if (peb == NULL || buf == NULL) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("pread: bad file descriptor");
        return -1;
    }

    node = (P9Node *)fd_entry->node_ptr;
    if (node == NULL) {
        p9_set_errstr("pread: no file attached");
        return -1;
    }

    offset = fd_entry->offset;

    /* TODO: Implement proper 9P read operation */
    /* For now, handle stdin/stdout/stderr specially */
    if (fd == 0) {
        /* stdin - read from host stdin */
        result = read(0, buf, count);
        if (result > 0) {
            fd_entry->offset += result;
        }
    } else {
        /* TODO: Read from 9P node */
        result = 0;  /* EOF */
        fprintf(stderr, "p9sys_pread: fd=%d count=%d (not implemented)\n", fd, count);
    }

    return result;
}

/*
 * Syscall: pwrite
 * Positional write
 */
int64_t p9sys_pwrite(PEB *peb, int fd, const void *buf, int count)
{
    P9FdEntry *fd_entry;
    int64_t result;

    if (peb == NULL || buf == NULL) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("pwrite: bad file descriptor");
        return -1;
    }

    /* Handle stdout/stderr specially */
    if (fd == 1) {
        result = write(1, buf, count);
    } else if (fd == 2) {
        result = write(2, buf, count);
    } else {
        /* TODO: Write to 9P node */
        result = count;
        fprintf(stderr, "p9sys_pwrite: fd=%d count=%d (not implemented)\n", fd, count);
    }

    if (result > 0) {
        fd_entry->offset += result;
    }

    return result;
}

/*
 * Syscall: close
 */
int64_t p9sys_close(PEB *peb, int fd)
{
    int result;

    if (peb == NULL) {
        return -1;
    }

    result = peb_close_fd(peb, fd);

    fprintf(stderr, "p9sys_close: fd=%d -> %d\n", fd, result);

    return (int64_t)result;
}

/*
 * Syscall: create
 */
int64_t p9sys_create(PEB *peb, const char *path, int mode, uint32_t perm)
{
    P9FdEntry *fd_entry;
    int fd;
    P9Node *root;
    P9Node *node;

    if (peb == NULL || path == NULL) {
        return -1;
    }

    /* TODO: Implement proper 9P create operation */
    /* For now, just allocate an fd */

    fd = peb_alloc_fd(peb);
    if (fd < 0) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry != NULL) {
        fd_entry->is_active = 1;
        fd_entry->mode = mode;
        fd_entry->offset = 0;
    }

    fprintf(stderr, "p9sys_create: path=%s mode=%d perm=0x%x -> fd=%d\n",
            path, mode, perm, fd);

    return (int64_t)fd;
}

/*
 * Syscall: remove
 */
int64_t p9sys_remove(PEB *peb, const char *path)
{
    if (peb == NULL || path == NULL) {
        return -1;
    }

    /* TODO: Implement proper 9P remove operation */
    fprintf(stderr, "p9sys_remove: path=%s\n", path);

    return 0;
}

/*
 * Syscall: seek
 */
int64_t p9sys_seek(PEB *peb, int fd, int64_t offset, int whence)
{
    P9FdEntry *fd_entry;
    int64_t new_offset;

    if (peb == NULL) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("seek: bad file descriptor");
        return -1;
    }

    switch (whence) {
        case P9_SEEK_SET:
            new_offset = offset;
            break;
        case P9_SEEK_CUR:
            new_offset = (int64_t)fd_entry->offset + offset;
            break;
        case P9_SEEK_END:
            /* TODO: Get file size */
            new_offset = offset;
            break;
        default:
            p9_set_errstr("seek: invalid whence");
            return -1;
    }

    if (new_offset < 0) {
        p9_set_errstr("seek: negative offset");
        return -1;
    }

    fd_entry->offset = (uint64_t)new_offset;

    fprintf(stderr, "p9sys_seek: fd=%d offset=%lld whence=%d -> %lld\n",
            fd, (long long)offset, whence, (long long)new_offset);

    return new_offset;
}

/*
 * Syscall: bind
 */
int64_t p9sys_bind(PEB *peb, const char *path, const char *spec, int flags)
{
    if (peb == NULL || path == NULL || spec == NULL) {
        return -1;
    }

    /* TODO: Implement proper 9P bind operation */
    fprintf(stderr, "p9sys_bind: path=%s spec=%s flags=%d\n", path, spec, flags);

    return 0;
}

/*
 * Syscall: mount
 */
int64_t p9sys_mount(PEB *peb, int fd, const char *spec, int flags,
                   const char *aname)
{
    if (peb == NULL || spec == NULL || aname == NULL) {
        return -1;
    }

    /* TODO: Implement proper 9P mount operation */
    fprintf(stderr, "p9sys_mount: fd=%d spec=%s flags=%d aname=%s\n",
            fd, spec, flags, aname);

    return 0;
}

/*
 * Syscall: unmount
 */
int64_t p9sys_unmount(PEB *peb, const char *spec, const char *where)
{
    if (peb == NULL || spec == NULL || where == NULL) {
        return -1;
    }

    /* TODO: Implement proper 9P unmount operation */
    fprintf(stderr, "p9sys_unmount: spec=%s where=%s\n", spec, where);

    return 0;
}

/*
 * Syscall: pipe
 * Based on 9front syspipe()
 */
int64_t p9sys_pipe(PEB *peb, int *fds)
{
    int fd0, fd1;
    P9FdEntry *fd0_entry, *fd1_entry;

    if (peb == NULL || fds == NULL) {
        return -1;
    }

    /* Allocate two file descriptors */
    fd0 = peb_alloc_fd(peb);
    if (fd0 < 0) {
        p9_set_errstr("pipe: no free file descriptors");
        return -1;
    }

    fd1 = peb_alloc_fd(peb);
    if (fd1 < 0) {
        peb_close_fd(peb, fd0);
        p9_set_errstr("pipe: no free file descriptors");
        return -1;
    }

    /* Initialize fd entries */
    fd0_entry = peb_get_fd(peb, fd0);
    fd1_entry = peb_get_fd(peb, fd1);

    if (fd0_entry != NULL) {
        fd0_entry->is_active = 1;
        fd0_entry->mode = P9_OREAD;
        fd0_entry->offset = 0;
        /* TODO: Create pipe node */
    }

    if (fd1_entry != NULL) {
        fd1_entry->is_active = 1;
        fd1_entry->mode = P9_OWRITE;
        fd1_entry->offset = 0;
        /* TODO: Create pipe node */
    }

    /* Return fds to caller */
    fds[0] = fd0;
    fds[1] = fd1;

    fprintf(stderr, "p9sys_pipe: -> [%d, %d]\n", fd0, fd1);

    return 0;
}

/*
 * Syscall: exits
 */
int64_t p9sys_exits(PEB *peb, const char *msg)
{
    if (peb == NULL) {
        return -1;
    }

    fprintf(stderr, "p9sys_exits: %s\n", msg ? msg : "(null)");

    /* Mark process as exiting */
    peb->state = P9_STATE_ZOMBIE;
    peb->exit_status = (msg != NULL) ? -1 : 0;

    /* TODO: Properly terminate process */

    return 0;  /* Should not return */
}

/*
 * Syscall: brk
 */
int64_t p9sys_brk(PEB *peb, void *addr)
{
    /* TODO: Implement memory management */
    fprintf(stderr, "p9sys_brk: addr=%p\n", addr);

    /* For now, always succeed */
    return 0;
}

/*
 * Syscall: sleep
 */
int64_t p9sys_sleep(PEB *peb, int milliseconds)
{
    if (peb == NULL) {
        return -1;
    }

    /* Convert milliseconds to microseconds for usleep */
    usleep(milliseconds * 1000);

    return 0;
}

/*
 * Syscall: rfork
 */
int64_t p9sys_rfork(PEB *peb, int flags)
{
    if (peb == NULL) {
        return -1;
    }

    /* TODO: Implement proper forking */
    /* For now, return error - not yet implemented */
    fprintf(stderr, "p9sys_rfork: flags=0x%x (not implemented)\n", flags);

    p9_set_errstr("rfork: not implemented");
    return -1;
}

/*
 * Syscall: dup
 */
int64_t p9sys_dup(PEB *peb, int fd, int newfd)
{
    P9FdEntry *fd_entry, *new_entry;

    if (peb == NULL) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("dup: bad file descriptor");
        return -1;
    }

    /* If newfd is -1, allocate a new one */
    if (newfd < 0) {
        newfd = peb_alloc_fd(peb);
        if (newfd < 0) {
            p9_set_errstr("dup: no free file descriptors");
            return -1;
        }
    } else {
        /* Close existing fd if open */
        P9FdEntry *existing = peb_get_fd(peb, newfd);
        if (existing != NULL && existing->is_active) {
            peb_close_fd(peb, newfd);
        }
    }

    /* Copy fd info */
    new_entry = peb_get_fd(peb, newfd);
    if (new_entry != NULL) {
        new_entry->is_active = 1;
        new_entry->node_ptr = fd_entry->node_ptr;
        new_entry->mode = fd_entry->mode;
        new_entry->offset = fd_entry->offset;
    }

    fprintf(stderr, "p9sys_dup: fd=%d -> newfd=%d\n", fd, newfd);

    return newfd;
}

/*
 * Syscall: fd2path
 */
int64_t p9sys_fd2path(PEB *peb, int fd, char *buf, int nbuf)
{
    P9FdEntry *fd_entry;

    if (peb == NULL || buf == NULL || nbuf <= 0) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("fd2path: bad file descriptor");
        return -1;
    }

    /* TODO: Get actual path from node */
    /* For now, return a placeholder */
    snprintf(buf, nbuf, "/dev/fd/%d", fd);

    return strlen(buf);
}

/*
 * Syscall: stat
 */
int64_t p9sys_stat(PEB *peb, const char *path, uint8_t *buf, int nbuf)
{
    if (peb == NULL || path == NULL || buf == NULL) {
        return -1;
    }

    /* TODO: Implement proper 9P stat operation */
    fprintf(stderr, "p9sys_stat: path=%s (not implemented)\n", path);

    p9_set_errstr("stat: not implemented");
    return -1;
}

/*
 * Syscall: fstat
 */
int64_t p9sys_fstat(PEB *peb, int fd, uint8_t *buf, int nbuf)
{
    P9FdEntry *fd_entry;

    if (peb == NULL || buf == NULL) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("fstat: bad file descriptor");
        return -1;
    }

    /* TODO: Implement proper 9P fstat operation */
    fprintf(stderr, "p9sys_fstat: fd=%d (not implemented)\n", fd);

    p9_set_errstr("fstat: not implemented");
    return -1;
}

/*
 * Syscall: wstat
 */
int64_t p9sys_wstat(PEB *peb, const char *path, uint8_t *buf, int nbuf)
{
    if (peb == NULL || path == NULL || buf == NULL) {
        return -1;
    }

    /* TODO: Implement proper 9P wstat operation */
    fprintf(stderr, "p9sys_wstat: path=%s (not implemented)\n", path);

    p9_set_errstr("wstat: not implemented");
    return -1;
}

/*
 * Syscall: fwstat
 */
int64_t p9sys_fwstat(PEB *peb, int fd, uint8_t *buf, int nbuf)
{
    P9FdEntry *fd_entry;

    if (peb == NULL || buf == NULL) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("fwstat: bad file descriptor");
        return -1;
    }

    /* TODO: Implement proper 9P fwstat operation */
    fprintf(stderr, "p9sys_fwstat: fd=%d (not implemented)\n", fd);

    p9_set_errstr("fwstat: not implemented");
    return -1;
}

/*
 * Syscall: segattach
 */
int64_t p9sys_segattach(PEB *peb, int type, const char *name,
                       void *addr, uint64_t len)
{
    if (peb == NULL) {
        return -1;
    }

    /* TODO: Implement segment attachment */
    fprintf(stderr, "p9sys_segattach: type=%d name=%s addr=%p len=%llu\n",
            type, name ? name : "(null)", addr, (unsigned long long)len);

    p9_set_errstr("segattach: not implemented");
    return -1;
}

/*
 * Syscall: segdetach
 */
int64_t p9sys_segdetach(PEB *peb, void *addr)
{
    if (peb == NULL) {
        return -1;
    }

    /* TODO: Implement segment detachment */
    fprintf(stderr, "p9sys_segdetach: addr=%p\n", addr);

    p9_set_errstr("segdetach: not implemented");
    return -1;
}

/*
 * Syscall: segfree
 */
int64_t p9sys_segfree(PEB *peb, void *addr, uint64_t len)
{
    if (peb == NULL) {
        return -1;
    }

    /* TODO: Implement segment freeing */
    fprintf(stderr, "p9sys_segfree: addr=%p len=%llu\n",
            addr, (unsigned long long)len);

    p9_set_errstr("segfree: not implemented");
    return -1;
}

/*
 * Syscall: segflush
 */
int64_t p9sys_segflush(PEB *peb, void *addr, uint64_t len)
{
    if (peb == NULL) {
        return -1;
    }

    /* TODO: Implement segment flushing */
    fprintf(stderr, "p9sys_segflush: addr=%p len=%llu\n",
            addr, (unsigned long long)len);

    /* For now, just succeed - this is often a no-op */
    return 0;
}

/*
 * Syscall: rendezvous
 */
int64_t p9sys_rendezvous(PEB *peb, uint64_t tag, uint64_t val)
{
    if (peb == NULL) {
        return -1;
    }

    /* TODO: Implement rendezvous */
    fprintf(stderr, "p9sys_rendezvous: tag=0x%llx val=0x%llx\n",
            (unsigned long long)tag, (unsigned long long)val);

    p9_set_errstr("rendezvous: not implemented");
    return -1;
}
