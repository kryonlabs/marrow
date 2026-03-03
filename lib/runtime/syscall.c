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
#include "namespace.h"
#include "loader/p9exec.h"
#include "runtime/context.h"
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
 * StaticFileData — dynamic buffer backing a created file
 */
typedef struct {
    uint8_t  *buf;
    uint64_t  len;
    uint64_t  cap;
} StaticFileData;

static ssize_t static_file_read(char *buf, size_t count, uint64_t offset,
                                void *vdata)
{
    StaticFileData *d = (StaticFileData *)vdata;
    uint64_t avail;
    if (d == NULL || offset >= d->len) return 0;
    avail = d->len - offset;
    if ((uint64_t)count > avail) count = (size_t)avail;
    memcpy(buf, d->buf + offset, count);
    return (ssize_t)count;
}

static ssize_t static_file_write(const char *buf, size_t count,
                                 uint64_t offset, void *vdata)
{
    StaticFileData *d = (StaticFileData *)vdata;
    uint64_t end;
    uint8_t *nb;
    if (d == NULL) return -1;
    end = offset + (uint64_t)count;
    if (end > d->cap) {
        nb = (uint8_t *)realloc(d->buf, (size_t)(end * 2));
        if (nb == NULL) return -1;
        d->buf = nb; d->cap = end * 2;
    }
    memcpy(d->buf + offset, buf, count);
    if (end > d->len) d->len = end;
    return (ssize_t)count;
}

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
            result = p9sys_pread(peb, (int)args[0], (void *)args[1],
                                 (int)args[2], (int64_t)args[3]);
            break;

        case P9_SYS_PWRITE:
            result = p9sys_pwrite(peb, (int)args[0], (const void *)args[1],
                                  (int)args[2], (int64_t)args[3]);
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

        case P9_SYS_CHDIR:
            result = p9sys_chdir(peb, (const char *)args[0]);
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

        case P9_SYS_EXEC:
            result = p9sys_exec(peb, (const char *)args[0], (char **)args[1]);
            break;

        case P9_SYS_ALARM:
            result = p9sys_alarm(peb, (uint32_t)args[0]);
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

        case P9_SYS_SEMACQUIRE:
            result = p9sys_semacquire(peb, (int *)args[0], (int)args[1]);
            break;

        case P9_SYS_SEMRELEASE:
            result = p9sys_semrelease(peb, (int *)args[0], (int)args[1]);
            break;

        case P9_SYS_TSEMACQUIRE:
            result = p9sys_tsemacquire(peb, (int *)args[0], (uint32_t)args[1]);
            break;

        /* Note (signal) system */
        case P9_SYS_NOTIFY:
            result = p9sys_notify(peb, (void *)args[0]);
            break;

        case P9_SYS_NOTED:
            result = p9sys_noted(peb, (int)args[0]);
            break;

        case P9_SYS_AWAIT:
            result = p9sys_await(peb, (char *)args[0], (int)args[1]);
            break;

        /* Error string */
        case P9_SYS_ERRSTR:
            result = p9sys_errstr(peb, (char *)args[0], (int)args[1]);
            break;

        /* Authentication stubs */
        case P9_SYS_FAUTH:
            p9_set_errstr("fauth: not implemented");
            result = -1;
            break;

        case P9_SYS_FVERSION:
            p9_set_errstr("fversion: not implemented");
            result = -1;
            break;

        /* Deprecated syscalls — forwarded to modern equivalents */
        case P9_SYS_SYSR1:
            result = 0;
            break;

        case P9_SYS__ERRSTR:
            result = p9sys_errstr(peb, (char *)args[0], 64);
            break;

        case P9_SYS__FSESSION:
            p9_set_errstr("fsession: deprecated");
            result = -1;
            break;

        case P9_SYS__FSTAT:
            result = p9sys_fstat(peb, (int)args[0], (uint8_t *)args[1],
                                 (int)args[2]);
            break;

        case P9_SYS_SEGBRK:
            result = p9sys_brk(peb, (void *)args[0]);
            break;

        case P9_SYS__MOUNT:
            p9_set_errstr("mount: deprecated, use mount(46)");
            result = -1;
            break;

        case P9_SYS__READ:
            result = p9sys_pread(peb, (int)args[0], (void *)args[1],
                                 (int)args[2], P9_NOSEEK);
            break;

        case P9_SYS_OSEEK:
            result = p9sys_seek(peb, (int)args[0], (int64_t)args[1], (int)args[2]);
            break;

        case P9_SYS__STAT:
            result = p9sys_stat(peb, (const char *)args[0], (uint8_t *)args[1],
                                (int)args[2]);
            break;

        case P9_SYS__WRITE:
            result = p9sys_pwrite(peb, (int)args[0], (const void *)args[1],
                                  (int)args[2], P9_NOSEEK);
            break;

        case P9_SYS__WSTAT:
            result = p9sys_wstat(peb, (const char *)args[0], (uint8_t *)args[1],
                                 (int)args[2]);
            break;

        case P9_SYS__FWSTAT:
            result = p9sys_fwstat(peb, (int)args[0], (uint8_t *)args[1],
                                  (int)args[2]);
            break;

        case P9_SYS__WAIT:
            p9_set_errstr("wait: deprecated");
            result = -1;
            break;

        case P9_SYS__NSEC:
            result = p9sys_nsec(peb);
            break;

        default:
            fprintf(stderr, "p9sys_gateway: unimplemented syscall %d\n",
                    syscall_num);
            p9_set_errstr("unimplemented syscall");
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
 * Positional read — if offset == P9_NOSEEK, use current fd offset and advance.
 */
int64_t p9sys_pread(PEB *peb, int fd, void *buf, int count, int64_t offset)
{
    P9FdEntry *fd_entry;
    int64_t result;
    P9Node *node;
    int use_seek;

    if (peb == NULL || buf == NULL) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("pread: bad file descriptor");
        return -1;
    }

    node = (P9Node *)fd_entry->node_ptr;
    use_seek = (offset == P9_NOSEEK);

    /* Host pipe fd passthrough */
    if (fd_entry->host_fd >= 0) {
        result = (int64_t)read(fd_entry->host_fd, buf, (size_t)count);
        return result;
    }

    if (fd == 0 && node == NULL) {
        /* stdin with no 9P node — read from host stdin */
        result = read(0, buf, (size_t)count);
        if (result > 0) {
            fd_entry->offset += (uint64_t)result;
        }
        return result;
    }

    if (node == NULL) {
        p9_set_errstr("pread: no file attached");
        return -1;
    }

    if (use_seek) {
        /* Use current position and advance after read */
        result = node_read(node, (char *)buf, (size_t)count, fd_entry->offset);
        if (result > 0) {
            fd_entry->offset += (uint64_t)result;
        }
    } else {
        /* Positional read — do not advance fd_entry->offset */
        result = node_read(node, (char *)buf, (size_t)count, (uint64_t)offset);
    }

    return result;
}

/*
 * Syscall: pwrite
 * Positional write — if offset == P9_NOSEEK, use current fd offset and advance.
 */
int64_t p9sys_pwrite(PEB *peb, int fd, const void *buf, int count, int64_t offset)
{
    P9FdEntry *fd_entry;
    int64_t result;
    P9Node *node;
    int use_seek;

    if (peb == NULL || buf == NULL) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("pwrite: bad file descriptor");
        return -1;
    }

    node = (P9Node *)fd_entry->node_ptr;
    use_seek = (offset == P9_NOSEEK);

    /* Host pipe fd passthrough */
    if (fd_entry->host_fd >= 0) {
        result = (int64_t)write(fd_entry->host_fd, buf, (size_t)count);
        return result;
    }

    if ((fd == 1 || fd == 2) && node == NULL) {
        /* stdout/stderr with no 9P node — write to host */
        result = write(fd, buf, (size_t)count);
        if (result > 0) {
            fd_entry->offset += (uint64_t)result;
        }
        return result;
    }

    if (node == NULL) {
        p9_set_errstr("pwrite: no file attached");
        return -1;
    }

    if (use_seek) {
        /* Use current position and advance after write */
        result = node_write(node, (const char *)buf, (size_t)count,
                            fd_entry->offset);
        if (result > 0) {
            uint64_t end = fd_entry->offset + (uint64_t)result;
            if (end > node->length) node->length = end;
            fd_entry->offset += (uint64_t)result;
        }
    } else {
        /* Positional write — do not advance fd_entry->offset */
        result = node_write(node, (const char *)buf, (size_t)count,
                            (uint64_t)offset);
        if (result > 0) {
            uint64_t end = (uint64_t)offset + (uint64_t)result;
            if (end > node->length) node->length = end;
        }
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
    P9Node *parent;
    P9Node *node;
    char dir[1024];
    const char *name;
    const char *slash;
    size_t dirlen;

    if (peb == NULL || path == NULL) {
        return -1;
    }

    /* Split path into directory and filename */
    slash = strrchr(path, '/');
    if (slash != NULL) {
        dirlen = (size_t)(slash - path);
        if (dirlen == 0) {
            dir[0] = '/'; dir[1] = '\0';
        } else if (dirlen < sizeof(dir)) {
            memcpy(dir, path, dirlen);
            dir[dirlen] = '\0';
        } else {
            p9_set_errstr("create: path too long");
            return -1;
        }
        name = slash + 1;
    } else {
        strncpy(dir, peb->cwd, sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = '\0';
        name = path;
    }

    parent = tree_lookup(tree_root(), dir);
    if (parent == NULL) {
        p9_set_errstr("create: parent directory not found");
        return -1;
    }

    if (perm & P9_DMDIR) {
        node = tree_create_dir(parent, name);
    } else {
        StaticFileData *sfd = (StaticFileData *)calloc(1, sizeof(StaticFileData));
        if (sfd == NULL) {
            p9_set_errstr("create: out of memory");
            return -1;
        }
        node = tree_create_file(parent, name, sfd,
                                (P9ReadFunc)static_file_read,
                                (P9WriteFunc)static_file_write);
        if (node == NULL) {
            free(sfd);
        }
    }

    if (node == NULL) {
        p9_set_errstr("create: failed to create node");
        return -1;
    }

    fd = peb_alloc_fd(peb);
    if (fd < 0) {
        p9_set_errstr("create: no free file descriptors");
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    fd_entry->is_active = 1;
    fd_entry->node_ptr = node;
    fd_entry->mode = mode;
    fd_entry->offset = 0;
    fd_entry->host_fd = -1;

    fprintf(stderr, "p9sys_create: path=%s mode=%d perm=0x%x -> fd=%d\n",
            path, mode, perm, fd);

    return (int64_t)fd;
}

/*
 * Syscall: remove
 */
int64_t p9sys_remove(PEB *peb, const char *path)
{
    P9Node *node;

    if (peb == NULL || path == NULL) {
        return -1;
    }

    node = tree_lookup(tree_root(), path);
    if (node == NULL) {
        p9_set_errstr("remove: file not found");
        return -1;
    }

    if (tree_remove_node(node) < 0) {
        p9_set_errstr("remove: failed");
        return -1;
    }

    fprintf(stderr, "p9sys_remove: path=%s -> ok\n", path);

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
        case P9_SEEK_END: {
            P9Node *seek_node = (P9Node *)fd_entry->node_ptr;
            uint64_t flen = (seek_node != NULL) ? seek_node->length : 0;
            new_offset = (int64_t)flen + offset;
            break;
        }
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
    NSBindType btype;

    if (peb == NULL || path == NULL || spec == NULL) {
        return -1;
    }

    /* Map Plan 9 mount flags to NSBindType */
    if (flags & 1)       btype = NS_BIND_BEFORE;
    else if (flags & 2)  btype = NS_BIND_AFTER;
    else                 btype = NS_BIND_REPLACE;

    if (namespace_bind(tree_root(), spec, path, btype) < 0) {
        p9_set_errstr("bind: failed");
        return -1;
    }

    fprintf(stderr, "p9sys_bind: spec=%s path=%s flags=%d -> ok\n",
            spec, path, flags);

    return 0;
}

/*
 * Syscall: mount
 */
int64_t p9sys_mount(PEB *peb, int fd, const char *spec, int flags,
                   const char *aname)
{
    (void)fd;
    (void)flags;
    (void)aname;

    if (peb == NULL || spec == NULL) {
        return -1;
    }

    /* 9P client session mount requires full 9P negotiation — not supported */
    p9_set_errstr("mount: not supported in this build");
    return -1;
}

/*
 * Syscall: unmount
 */
int64_t p9sys_unmount(PEB *peb, const char *spec, const char *where)
{
    (void)spec;

    if (peb == NULL || where == NULL) {
        return -1;
    }

    if (namespace_unbind(where) < 0) {
        p9_set_errstr("unmount: failed");
        return -1;
    }

    fprintf(stderr, "p9sys_unmount: where=%s -> ok\n", where);

    return 0;
}

/*
 * Syscall: pipe
 * Based on 9front syspipe()
 */
int64_t p9sys_pipe(PEB *peb, int *fds)
{
    int pfd[2];
    int fd0, fd1;
    P9FdEntry *fd0_entry, *fd1_entry;

    if (peb == NULL || fds == NULL) {
        return -1;
    }

    /* Create host pipe */
    if (pipe(pfd) < 0) {
        p9_set_errstr("pipe: host pipe failed");
        return -1;
    }

    /* Allocate two P9 file descriptors */
    fd0 = peb_alloc_fd(peb);
    fd1 = (fd0 >= 0) ? peb_alloc_fd(peb) : -1;

    if (fd0 < 0 || fd1 < 0) {
        if (fd0 >= 0) peb_close_fd(peb, fd0);
        close(pfd[0]);
        close(pfd[1]);
        p9_set_errstr("pipe: no free file descriptors");
        return -1;
    }

    /* Wire read end */
    fd0_entry = peb_get_fd(peb, fd0);
    fd0_entry->is_active = 1;
    fd0_entry->node_ptr  = NULL;
    fd0_entry->mode      = P9_OREAD;
    fd0_entry->offset    = 0;
    fd0_entry->host_fd   = pfd[0];

    /* Wire write end */
    fd1_entry = peb_get_fd(peb, fd1);
    fd1_entry->is_active = 1;
    fd1_entry->node_ptr  = NULL;
    fd1_entry->mode      = P9_OWRITE;
    fd1_entry->offset    = 0;
    fd1_entry->host_fd   = pfd[1];

    fds[0] = fd0;
    fds[1] = fd1;

    fprintf(stderr, "p9sys_pipe: -> [%d, %d] (host %d, %d)\n",
            fd0, fd1, pfd[0], pfd[1]);

    return 0;
}

/*
 * Syscall: exits
 */
int64_t p9sys_exits(PEB *peb, const char *msg)
{
    int i;

    if (peb == NULL) {
        exit(1);
    }

    fprintf(stderr, "p9sys_exits: %s\n", msg ? msg : "(null)");

    /* Close all open file descriptors */
    for (i = 0; i < P9_MAX_FDS; i++) {
        if (peb->fds[i].is_active) {
            peb_close_fd(peb, i);
        }
    }

    peb->state = P9_STATE_ZOMBIE;
    peb->exit_status = (msg == NULL || msg[0] == '\0') ? 0 : 1;

    exit(peb->exit_status);
    return 0; /* unreachable */
}

/*
 * Syscall: brk
 * Extend the data/bss segment to the given address.
 */
int64_t p9sys_brk(PEB *peb, void *addr)
{
    void *result;
    uintptr_t new_brk;
    uintptr_t cur_brk;

    if (peb == NULL) {
        return -1;
    }

    if (addr == NULL) {
        return 0;
    }

    /* Ask Linux to set the program break */
    new_brk = (uintptr_t)addr;
    result = (void *)syscall(SYS_brk, new_brk);
    cur_brk = (uintptr_t)result;

    if (cur_brk < new_brk) {
        p9_set_errstr("brk: out of memory");
        return -1;
    }

    /* Update bss segment size tracking */
    if (peb->bss.base != NULL) {
        uintptr_t base = (uintptr_t)peb->bss.base;
        if (cur_brk > base) {
            peb->bss.size = (uint32_t)(cur_brk - base);
        }
    }

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
 * Creates or modifies a process (plan9 fork with namespace flags).
 */
int64_t p9sys_rfork(PEB *peb, int flags)
{
    pid_t pid;

    if (peb == NULL) {
        return -1;
    }

    if (flags & P9_RFPROC) {
        /* Actual fork */
        pid = fork();
        if (pid < 0) {
            p9_set_errstr("rfork: fork failed");
            return -1;
        }
        /* Both parent and child record the flags */
        peb->rfork_flags |= flags;
        return (int64_t)pid;
    }

    if (flags & P9_RFMEM) {
        /* Share address space — complex, not yet implemented */
        p9_set_errstr("rfork: RFMEM not implemented");
        return -1;
    }

    /* Namespace/group flags without RFPROC: just record and succeed */
    if (flags & (P9_RFNAMEG | P9_RFENVG | P9_RFFDG |
                 P9_RFNOTEG | P9_RFNOWAIT)) {
        peb->rfork_flags |= flags;
        return 0;
    }

    /* Unknown flags — succeed silently */
    peb->rfork_flags |= flags;
    return 0;
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
 * Build a path string by walking the P9Node parent chain.
 * Returns the length written (without null terminator).
 */
static int p9_build_nodepath(P9Node *node, char *buf, int nbuf)
{
    const char *parts[64];
    int nparts = 0;
    P9Node *n;
    char *p;
    int i, len, partlen;

    n = node;
    while (n != NULL && nparts < 64) {
        if (n->name != NULL && n->name[0] != '\0' &&
            strcmp(n->name, "/") != 0) {
            parts[nparts++] = n->name;
        }
        if (n->parent == NULL || n->parent == n) {
            break;
        }
        n = n->parent;
    }

    /* Build path in reverse (parts[nparts-1] is root component) */
    p = buf;
    len = 0;

    if (len + 1 >= nbuf) {
        buf[0] = '\0';
        return 0;
    }
    *p++ = '/';
    len = 1;

    for (i = nparts - 1; i >= 0; i--) {
        partlen = (int)strlen(parts[i]);
        /* Add '/' separator before each component after the first */
        if (i < nparts - 1) {
            if (len + 1 >= nbuf) break;
            *p++ = '/';
            len++;
        }
        if (len + partlen >= nbuf) break;
        memcpy(p, parts[i], (size_t)partlen);
        p += partlen;
        len += partlen;
    }

    *p = '\0';
    return len;
}

/*
 * Syscall: fd2path
 */
int64_t p9sys_fd2path(PEB *peb, int fd, char *buf, int nbuf)
{
    P9FdEntry *fd_entry;
    P9Node *node;
    int len;

    if (peb == NULL || buf == NULL || nbuf <= 0) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("fd2path: bad file descriptor");
        return -1;
    }

    node = (P9Node *)fd_entry->node_ptr;
    if (node == NULL) {
        /* No 9P node — return well-known names for std fds */
        if (fd == 0) {
            strncpy(buf, "/dev/stdin", (size_t)nbuf);
        } else if (fd == 1) {
            strncpy(buf, "/dev/stdout", (size_t)nbuf);
        } else if (fd == 2) {
            strncpy(buf, "/dev/stderr", (size_t)nbuf);
        } else {
            snprintf(buf, (size_t)nbuf, "/dev/fd/%d", fd);
        }
        buf[nbuf - 1] = '\0';
        return (int64_t)strlen(buf);
    }

    len = p9_build_nodepath(node, buf, nbuf);
    return (int64_t)len;
}

/*
 * Pack a P9Node into Plan 9 stat wire format:
 *   size[2] type[2] dev[4] qid[13] mode[4] atime[4] mtime[4]
 *   length[8] name[s] uid[s] gid[s] muid[s]
 *
 * The leading size[2] field contains the byte count of the remainder.
 * Returns total bytes written, or -1 if buf is too small.
 */
static int64_t p9_pack_node_stat(P9Node *node, uint8_t *buf, int nbuf)
{
    const char *name;
    const char *uid  = "none";
    const char *gid  = "none";
    const char *muid = "";
    int namelen, uidlen, gidlen, muidlen;
    int statlen, totallen;
    uint8_t *p;

    name    = (node->name != NULL) ? node->name : "";
    namelen = (int)strlen(name);
    uidlen  = (int)strlen(uid);
    gidlen  = (int)strlen(gid);
    muidlen = (int)strlen(muid);

    /*
     * Fixed-size stat body (excluding the leading size[2] and strings):
     *   type[2] dev[4] qid[13] mode[4] atime[4] mtime[4] length[8] = 39 bytes
     * String headers: 4 * 2-byte length prefix = 8 bytes
     * Strings: namelen + uidlen + gidlen + muidlen bytes
     */
    statlen  = 2 + 4 + 13 + 4 + 4 + 4 + 8  /* fixed fields */
             + 2 + namelen
             + 2 + uidlen
             + 2 + gidlen
             + 2 + muidlen;
    totallen = 2 + statlen;   /* leading size[2] + body */

    if (nbuf < totallen) {
        p9_set_errstr("stat: buffer too small");
        return -1;
    }

    p = buf;

    /* size[2] — byte count of everything after this field */
    le_put16(p, (uint16_t)statlen); p += 2;

    /* type[2] */
    le_put16(p, 0); p += 2;

    /* dev[4] */
    le_put32(p, 0); p += 4;

    /* qid: type[1] vers[4] path[8] */
    *p++ = node->qid.type;
    le_put32(p, node->qid.version); p += 4;
    le_put64(p, node->qid.path);    p += 8;

    /* mode[4] */
    le_put32(p, node->mode); p += 4;

    /* atime[4] */
    le_put32(p, node->atime); p += 4;

    /* mtime[4] */
    le_put32(p, node->mtime); p += 4;

    /* length[8] */
    le_put64(p, node->length); p += 8;

    /* name[s] */
    le_put16(p, (uint16_t)namelen); p += 2;
    memcpy(p, name, (size_t)namelen); p += namelen;

    /* uid[s] */
    le_put16(p, (uint16_t)uidlen); p += 2;
    memcpy(p, uid, (size_t)uidlen); p += uidlen;

    /* gid[s] */
    le_put16(p, (uint16_t)gidlen); p += 2;
    memcpy(p, gid, (size_t)gidlen); p += gidlen;

    /* muid[s] */
    le_put16(p, (uint16_t)muidlen); p += 2;
    memcpy(p, muid, (size_t)muidlen); p += muidlen;

    (void)p; /* suppress unused warning */
    return (int64_t)totallen;
}

/*
 * Unpack a Plan 9 stat wire buffer into a P9Node (for wstat/fwstat).
 * Only updates fields that are not set to their "don't change" sentinel.
 * Returns 0 on success, -1 on parse error.
 */
static int p9_unpack_stat_to_node(const uint8_t *buf, int nbuf, P9Node *node)
{
    const uint8_t *p;
    uint32_t mode, atime, mtime;
    uint64_t length;
    uint16_t nameLen;
    char name[P9_MAX_STR];

    if (nbuf < 2) {
        return -1;
    }

    /* Skip size[2] */
    p = buf + 2;

    /* type[2] dev[4] */
    if (p + 6 > buf + nbuf) return -1;
    p += 6;

    /* qid[13] */
    if (p + 13 > buf + nbuf) return -1;
    p += 13;

    /* mode[4] */
    if (p + 4 > buf + nbuf) return -1;
    mode = le_get32(p); p += 4;

    /* atime[4] */
    if (p + 4 > buf + nbuf) return -1;
    atime = le_get32(p); p += 4;

    /* mtime[4] */
    if (p + 4 > buf + nbuf) return -1;
    mtime = le_get32(p); p += 4;

    /* length[8] */
    if (p + 8 > buf + nbuf) return -1;
    length = le_get64(p); p += 8;

    /* name[s] */
    if (p + 2 > buf + nbuf) return -1;
    nameLen = le_get16(p); p += 2;
    if (p + nameLen > buf + nbuf) return -1;
    if (nameLen > 0 && nameLen < P9_MAX_STR) {
        memcpy(name, p, (size_t)nameLen);
        name[nameLen] = '\0';
        /* Don't rename root ("/") */
        if (name[0] != '\0' && strcmp(name, "/") != 0 && node->parent != NULL) {
            free(node->name);
            node->name = (char *)malloc((size_t)nameLen + 1);
            if (node->name != NULL) {
                memcpy(node->name, name, (size_t)nameLen + 1);
            }
        }
    }
    p += nameLen;

    /* Apply numeric fields if not the "don't change" sentinel */
    if (mode != 0xFFFFFFFFU) {
        node->mode = mode;
    }
    if (atime != 0xFFFFFFFFU) {
        node->atime = atime;
    }
    if (mtime != 0xFFFFFFFFU) {
        node->mtime = mtime;
    }
    if (length != (uint64_t)-1LL) {
        node->length = length;
    }

    (void)p;
    return 0;
}

/*
 * Syscall: stat
 */
int64_t p9sys_stat(PEB *peb, const char *path, uint8_t *buf, int nbuf)
{
    P9Node *node;

    if (peb == NULL || path == NULL || buf == NULL) {
        return -1;
    }

    node = tree_lookup(tree_root(), path);
    if (node == NULL) {
        p9_set_errstr("stat: file not found");
        return -1;
    }

    return p9_pack_node_stat(node, buf, nbuf);
}

/*
 * Syscall: fstat
 */
int64_t p9sys_fstat(PEB *peb, int fd, uint8_t *buf, int nbuf)
{
    P9FdEntry *fd_entry;
    P9Node *node;

    if (peb == NULL || buf == NULL) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("fstat: bad file descriptor");
        return -1;
    }

    node = (P9Node *)fd_entry->node_ptr;
    if (node == NULL) {
        p9_set_errstr("fstat: no file attached");
        return -1;
    }

    return p9_pack_node_stat(node, buf, nbuf);
}

/*
 * Syscall: wstat
 */
int64_t p9sys_wstat(PEB *peb, const char *path, uint8_t *buf, int nbuf)
{
    P9Node *node;

    if (peb == NULL || path == NULL || buf == NULL) {
        return -1;
    }

    node = tree_lookup(tree_root(), path);
    if (node == NULL) {
        p9_set_errstr("wstat: file not found");
        return -1;
    }

    return (int64_t)p9_unpack_stat_to_node(buf, nbuf, node);
}

/*
 * Syscall: fwstat
 */
int64_t p9sys_fwstat(PEB *peb, int fd, uint8_t *buf, int nbuf)
{
    P9FdEntry *fd_entry;
    P9Node *node;

    if (peb == NULL || buf == NULL) {
        return -1;
    }

    fd_entry = peb_get_fd(peb, fd);
    if (fd_entry == NULL || !fd_entry->is_active) {
        p9_set_errstr("fwstat: bad file descriptor");
        return -1;
    }

    node = (P9Node *)fd_entry->node_ptr;
    if (node == NULL) {
        p9_set_errstr("fwstat: no file attached");
        return -1;
    }

    return (int64_t)p9_unpack_stat_to_node(buf, nbuf, node);
}

/*
 * Syscall: segattach
 * Plan 9 attr flags: SG_RONLY=1, SG_NOEXEC=4
 */
int64_t p9sys_segattach(PEB *peb, int attr, const char *name,
                       void *va, uint64_t len)
{
    void *result;
    int prot;
    int i;

    if (peb == NULL) {
        return -1;
    }

    if (len == 0) {
        p9_set_errstr("segattach: zero length");
        return -1;
    }

    prot = PROT_READ | PROT_WRITE;
    if (attr & 1) {
        prot = PROT_READ;            /* SG_RONLY */
    }
    if (!(attr & 4)) {
        prot |= PROT_EXEC;           /* not SG_NOEXEC → executable */
    }

    result = mmap(va, (size_t)len, prot,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (result == MAP_FAILED) {
        p9_set_errstr("segattach: mmap failed");
        return -1;
    }

    /* Track in PEB so segdetach can find the length */
    for (i = 0; i < P9_MAX_ATTACHED_SEGS; i++) {
        if (!peb->attached_segs[i].active) {
            peb->attached_segs[i].addr   = result;
            peb->attached_segs[i].len    = len;
            peb->attached_segs[i].active = 1;
            break;
        }
    }

    (void)name; /* segment class name not used in hosted env */
    return (int64_t)(uintptr_t)result;
}

/*
 * Syscall: segdetach
 */
int64_t p9sys_segdetach(PEB *peb, void *addr)
{
    int i;

    if (peb == NULL) {
        return -1;
    }

    for (i = 0; i < P9_MAX_ATTACHED_SEGS; i++) {
        if (peb->attached_segs[i].active &&
            peb->attached_segs[i].addr == addr) {
            munmap(addr, (size_t)peb->attached_segs[i].len);
            peb->attached_segs[i].active = 0;
            return 0;
        }
    }

    p9_set_errstr("segdetach: segment not found");
    return -1;
}

/*
 * Syscall: segfree
 * Frees a segment by address and length.
 */
int64_t p9sys_segfree(PEB *peb, void *addr, uint64_t len)
{
    int i;

    if (peb == NULL) {
        return -1;
    }

    /* Remove from tracking table if present */
    for (i = 0; i < P9_MAX_ATTACHED_SEGS; i++) {
        if (peb->attached_segs[i].active &&
            peb->attached_segs[i].addr == addr) {
            peb->attached_segs[i].active = 0;
            break;
        }
    }

    munmap(addr, (size_t)len);
    return 0;
}

/*
 * Syscall: segflush
 * Flush dirty pages in a segment (write-back).  msync() is sufficient.
 */
int64_t p9sys_segflush(PEB *peb, void *addr, uint64_t len)
{
    if (peb == NULL) {
        return -1;
    }

    msync(addr, (size_t)len, MS_SYNC);
    return 0;
}

/*
 * Syscall: rendezvous
 * Two callers meet at the same tag; each gets the other's value.
 * Uses a global table protected by a spinlock and per-slot futex.
 */
int64_t p9sys_rendezvous(PEB *peb, uint64_t tag, uint64_t val)
{
    int i;
    uint64_t their_val;

    if (peb == NULL) {
        return -1;
    }

    /* Acquire spinlock */
    while (__sync_lock_test_and_set(&g_rendlock, 1)) {
        /* spin */
    }

    /* Search for a waiter with matching tag */
    for (i = 0; i < P9_REND_SIZE; i++) {
        if (g_rendtable[i].active && g_rendtable[i].tag == tag) {
            their_val = g_rendtable[i].val;
            g_rendtable[i].val   = val;  /* hand our value to the waiter */
            g_rendtable[i].futex = 0;    /* signal wakeup */
            __sync_lock_release(&g_rendlock);
            /* Wake the sleeping first caller */
            syscall(SYS_futex, (int *)&g_rendtable[i].futex,
                    FUTEX_WAKE, 1, NULL, NULL, 0);
            return (int64_t)their_val;
        }
    }

    /* No waiter found — become the first caller */
    for (i = 0; i < P9_REND_SIZE; i++) {
        if (!g_rendtable[i].active) {
            g_rendtable[i].tag    = tag;
            g_rendtable[i].val    = val;
            g_rendtable[i].futex  = 1;
            g_rendtable[i].active = 1;
            __sync_lock_release(&g_rendlock);

            /* Sleep until second caller sets futex = 0 */
            while (__atomic_load_n((int *)&g_rendtable[i].futex,
                                   __ATOMIC_SEQ_CST)) {
                syscall(SYS_futex, (int *)&g_rendtable[i].futex,
                        FUTEX_WAIT, 1, NULL, NULL, 0);
            }

            their_val = g_rendtable[i].val;

            /* Mark slot free under lock */
            while (__sync_lock_test_and_set(&g_rendlock, 1)) {}
            g_rendtable[i].active = 0;
            __sync_lock_release(&g_rendlock);

            return (int64_t)their_val;
        }
    }

    __sync_lock_release(&g_rendlock);
    p9_set_errstr("rendezvous: table full");
    return -1;
}

/*
 * Syscall: errstr
 * Copy the current error string into buf (up to len bytes, null-terminated).
 */
int64_t p9sys_errstr(PEB *peb, char *buf, int len)
{
    const char *err;
    int n;

    if (buf == NULL || len <= 0) {
        return -1;
    }
    (void)peb;

    err = p9_get_errstr();
    if (err == NULL) {
        err = "";
    }

    n = (int)strlen(err);
    if (n >= len) {
        n = len - 1;
    }
    memcpy(buf, err, (size_t)n);
    buf[n] = '\0';
    return 0;
}

/*
 * Syscall: chdir
 * Change the process working directory in the 9P namespace.
 */
int64_t p9sys_chdir(PEB *peb, const char *path)
{
    P9Node *node;
    char full_path[1024];

    if (peb == NULL || path == NULL) {
        p9_set_errstr("chdir: invalid argument");
        return -1;
    }

    if (path[0] == '/') {
        /* Absolute path */
        node = tree_lookup(tree_root(), path);
    } else {
        /* Relative — resolve against current cwd */
        snprintf(full_path, sizeof(full_path), "%s/%s", peb->cwd, path);
        node = tree_lookup(tree_root(), full_path);
        path = full_path;
    }

    if (node == NULL) {
        p9_set_errstr("chdir: directory not found");
        return -1;
    }

    if (!(node->mode & P9_DMDIR)) {
        p9_set_errstr("chdir: not a directory");
        return -1;
    }

    strncpy(peb->cwd, path, sizeof(peb->cwd) - 1);
    peb->cwd[sizeof(peb->cwd) - 1] = '\0';
    return 0;
}

/*
 * Syscall: alarm
 * Set a process alarm in milliseconds.
 */
int64_t p9sys_alarm(PEB *peb, uint32_t ms)
{
    struct itimerval it;

    (void)peb;

    memset(&it, 0, sizeof(it));
    it.it_value.tv_sec  = (long)(ms / 1000U);
    it.it_value.tv_usec = (long)((ms % 1000U) * 1000U);

    setitimer(ITIMER_REAL, &it, NULL);
    return 0;
}

/*
 * Syscall: semacquire
 * Decrement *addr if > 0, else block (if block==1) or return -1.
 */
int64_t p9sys_semacquire(PEB *peb, int *addr, int block)
{
    int val;

    if (peb == NULL || addr == NULL) {
        return -1;
    }

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
            p9_set_errstr("semacquire: would block");
            return -1;
        }
        /* Block until someone releases */
        syscall(SYS_futex, addr, FUTEX_WAIT, 0, NULL, NULL, 0);
    }
}

/*
 * Syscall: semrelease
 * Increment *addr by count and wake blocked acquirers.
 */
int64_t p9sys_semrelease(PEB *peb, int *addr, int count)
{
    if (peb == NULL || addr == NULL) {
        return -1;
    }

    __atomic_add_fetch(addr, count, __ATOMIC_SEQ_CST);
    syscall(SYS_futex, addr, FUTEX_WAKE, count, NULL, NULL, 0);
    return (int64_t)count;
}

/*
 * Syscall: tsemacquire
 * Like semacquire but with a millisecond timeout.
 */
int64_t p9sys_tsemacquire(PEB *peb, int *addr, uint32_t ms)
{
    int val;
    struct timespec ts;
    long rc;

    if (peb == NULL || addr == NULL) {
        return -1;
    }

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
            p9_set_errstr("tsemacquire: timeout");
            return -1;
        }
    }
}

/*
 * Syscall: notify
 * Register a per-process note (signal-like) handler.
 */
int64_t p9sys_notify(PEB *peb, void *fn)
{
    if (peb == NULL) {
        return -1;
    }

    peb->notify_fn = (void (*)(void *, char *))fn;
    return 0;
}

/*
 * Syscall: noted
 * Called from a note handler to acknowledge the note.
 * v == 1 (NCONT): continue after the note.
 * v == 0 (NDFLT): perform the default action (terminate).
 */
int64_t p9sys_noted(PEB *peb, int v)
{
    if (peb == NULL) {
        return -1;
    }

    peb->note_pending = 0;
    peb->pending_note[0] = '\0';

    if (v == 0) {
        /* Default action — exit the process */
        peb->state = P9_STATE_ZOMBIE;
        peb->exit_status = -1;
        exit(1);
    }

    /* v == 1 (NCONT): continue execution */
    return 0;
}

/*
 * Syscall: await
 * Wait for an incoming note; copy it into buf.
 */
int64_t p9sys_await(PEB *peb, char *buf, int len)
{
    int n;

    if (peb == NULL || buf == NULL || len <= 0) {
        return -1;
    }

    if (!peb->note_pending) {
        /* No note pending — return empty (non-blocking in simple impl) */
        buf[0] = '\0';
        return 0;
    }

    n = (int)strlen(peb->pending_note);
    if (n >= len) {
        n = len - 1;
    }
    memcpy(buf, peb->pending_note, (size_t)n);
    buf[n] = '\0';

    peb->note_pending = 0;
    peb->pending_note[0] = '\0';
    return (int64_t)n;
}

/*
 * Syscall: exec
 * Execute a Plan 9 binary from the 9P namespace.
 * Full implementation requires loader integration — stub for now.
 */
int64_t p9sys_exec(PEB *peb, const char *path, char **argv)
{
    P9Node *node;
    uint64_t flen;
    uint8_t *buf;
    int64_t n;
    const char *cmd;
    PEB *new_peb;
    int i;

    if (peb == NULL || path == NULL) {
        p9_set_errstr("exec: invalid argument");
        return -1;
    }

    node = tree_lookup(tree_root(), path);
    if (node == NULL) {
        p9_set_errstr("exec: not found");
        return -1;
    }

    flen = node->length;
    if (flen == 0) {
        p9_set_errstr("exec: empty file");
        return -1;
    }

    buf = (uint8_t *)malloc((size_t)flen);
    if (buf == NULL) {
        p9_set_errstr("exec: out of memory");
        return -1;
    }

    n = (int64_t)node_read(node, (char *)buf, (size_t)flen, 0);
    if (n <= 0) {
        free(buf);
        p9_set_errstr("exec: read failed");
        return -1;
    }

    cmd = (argv != NULL && argv[0] != NULL) ? argv[0] : path;
    new_peb = p9_load_executable_from_memory(buf, (size_t)n, cmd);
    free(buf);

    if (new_peb == NULL) {
        p9_set_errstr("exec: load failed");
        return -1;
    }

    /* Inherit fd table and cwd from old process */
    for (i = 0; i < P9_MAX_FDS; i++) {
        new_peb->fds[i] = peb->fds[i];
    }
    strncpy(new_peb->cwd, peb->cwd, sizeof(new_peb->cwd) - 1);
    new_peb->cwd[sizeof(new_peb->cwd) - 1] = '\0';

    fprintf(stderr, "p9sys_exec: path=%s -> entering new binary\n", path);

    amd64_enter_plan9(new_peb); /* noreturn */
    return -1; /* unreachable */
}

/*
 * Syscall: _nsec (deprecated)
 * Returns the current time in nanoseconds (monotonic clock).
 */
int64_t p9sys_nsec(PEB *peb)
{
    struct timespec ts;

    (void)peb;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}
