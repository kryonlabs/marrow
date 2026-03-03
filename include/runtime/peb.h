#ifndef PEB_H
#define PEB_H

#include <stddef.h>
#include <stdint.h>

/*
 * Plan 9 Assembly Support - Process Environment Block
 * C89/C90 compliant
 *
 * This header defines the Process Environment Block (PEB) which tracks
 * the complete execution state of a Plan 9 process within Marrow.
 */

/*
 * Process state enumeration
 */
typedef enum {
    P9_STATE_READY = 0,
    P9_STATE_RUNNING = 1,
    P9_STATE_BLOCKED = 2,
    P9_STATE_ZOMBIE = 3
} P9State;

/*
 * Memory segment descriptor
 */
typedef struct {
    uint8_t *base;       /* Base address of segment */
    uint32_t size;       /* Size in bytes */
    uint32_t perms;      /* Permissions (rwx) */
} P9Segment;

/*
 * Segment permission flags
 */
#define P9_PERM_READ    0x1
#define P9_PERM_WRITE   0x2
#define P9_PERM_EXEC    0x4

/*
 * Symbol table entry
 * Plan 9 symbol table format from 6l/8l/5l linkers
 */
typedef struct {
    char *name;          /* Symbol name (allocated) */
    uint64_t value;      /* Symbol value (address or constant) */
    uint8_t type;        /* Symbol type (T_TEXT, T_DATA, etc.) */
} P9Symbol;

/*
 * Symbol types (from Plan 9/obj.h)
 */
#define P9_SYM_TEXT     'T'
#define P9_SYM_DATA     'D'
#define P9_SYM_BSS      'B'
#define P9_SYM_FILE     'f'
#define P9_SYM_UNDEF    'U'

/*
 * Ureg structure - Plan 9 register save area
 * This matches the Plan 9 kernel's Ureg structure for amd64
 * CRITICAL: In Plan 9 amd64, R15 MUST point to this Ureg structure!
 */
typedef struct {
    uint64_t ax;         /* RAX */
    uint64_t bx;         /* RBX */
    uint64_t cx;         /* RCX */
    uint64_t dx;         /* RDX */
    uint64_t si;         /* RSI */
    uint64_t di;         /* RDI */
    uint64_t bp;         /* RBP */
    uint64_t r8;         /* R8 */
    uint64_t r9;         /* R9 */
    uint64_t r10;        /* R10 */
    uint64_t r11;        /* R11 */
    uint64_t r12;        /* R12 */
    uint64_t r13;        /* R13 */
    uint64_t r14;        /* R14 */
    uint64_t r15;        /* R15 (MUST point to Ureg in Plan 9!) */
    uint64_t ip;         /* Instruction pointer (RIP) */
    uint64_t flags;      /* Flags (RFLAGS) */
    uint64_t sp;         /* Stack pointer (RSP) */
} P9Ureg;

/*
 * File descriptor table entry
 * Tracks open files for Plan 9 processes
 */
typedef struct {
    int is_active;
    void *node_ptr;      /* Pointer to P9Node */
    int mode;            /* Open mode (P9_OREAD, etc.) */
    uint64_t offset;     /* Current file offset */
} P9FdEntry;

/*
 * Maximum file descriptors per process
 */
#define P9_MAX_FDS  64

/*
 * Attached segment tracking for segattach/segdetach
 */
typedef struct {
    void     *addr;
    uint64_t  len;
    int       active;
} P9AttachedSeg;

#define P9_MAX_ATTACHED_SEGS 16

/*
 * Maximum note string length
 */
#define P9_ERRMAX 128

/*
 * Process Environment Block (PEB)
 * Complete tracking structure for a Plan 9 process
 */
typedef struct {
    /* Process identification */
    int pid;                     /* Process ID */
    char cmd[64];                /* Command name */
    int active;                  /* Active flag */

    /* Memory layout */
    P9Segment text;              /* Text (code) segment */
    P9Segment data;              /* Data segment */
    P9Segment bss;               /* BSS segment */
    P9Segment stack;             /* Stack segment */

    /* Symbol table */
    P9Symbol *symbols;           /* Array of symbols */
    int nsymbols;                /* Number of symbols */
    int symbol_capacity;         /* Allocated capacity */

    /* Execution state */
    P9Ureg regs;                 /* Register state */
    P9State state;               /* Process state */
    int exit_status;             /* Exit status code */

    /* File descriptor table */
    P9FdEntry fds[P9_MAX_FDS];   /* File descriptor table */

    /* Syscall interception */
    void *syscall_gateway;       /* Pointer to syscall gateway */

    /* Entry point */
    uint64_t entry;              /* Entry point address */

    /* Current working directory */
    char cwd[1024];

    /* Note (signal) system */
    void (*notify_fn)(void *, char *);        /* Notification handler */
    char pending_note[P9_ERRMAX];             /* Pending note string */
    int  note_pending;                        /* Note pending flag */

    /* Fork flags inherited via rfork */
    int rfork_flags;

    /* Attached segments (segattach/segdetach) */
    P9AttachedSeg attached_segs[P9_MAX_ATTACHED_SEGS];
} PEB;

/*
 * PEB Management API
 */

/*
 * Create a new Process Environment Block
 * Returns allocated PEB on success, NULL on error
 */
PEB *peb_create(void);

/*
 * Destroy a PEB and free all associated memory
 * Including all segments, symbol table, and stack
 */
void peb_destroy(PEB *peb);

/*
 * Allocate a memory segment with specified permissions
 * Returns 0 on success, -1 on error
 */
int peb_alloc_segment(PEB *peb, P9Segment *seg, uint32_t size, uint32_t perms);

/*
 * Setup stack with guard pages
 * Creates stack with guard page at bottom for overflow detection
 * Returns 0 on success, -1 on error
 */
int peb_setup_stack(PEB *peb, uint32_t stack_size);

/*
 * Symbol table management
 */

/*
 * Add a symbol to the PEB's symbol table
 * Returns 0 on success, -1 on error
 */
int peb_add_symbol(PEB *peb, const char *name, uint64_t value, uint8_t type);

/*
 * Find a symbol by name
 * Returns symbol pointer if found, NULL if not found
 */
P9Symbol *peb_find_symbol(PEB *peb, const char *name);

/*
 * Sort symbols by name (for binary search)
 */
void peb_sort_symbols(PEB *peb);

/*
 * File descriptor management
 */

/*
 * Allocate a new file descriptor
 * Returns fd number on success, -1 on error
 */
int peb_alloc_fd(PEB *peb);

/*
 * Close a file descriptor
 * Returns 0 on success, -1 on error
 */
int peb_close_fd(PEB *peb, int fd);

/*
 * Get file descriptor entry
 * Returns pointer to entry or NULL if invalid
 */
P9FdEntry *peb_get_fd(PEB *peb, int fd);

/*
 * Utility functions
 */

/*
 * Print PEB information for debugging
 */
void peb_print_info(PEB *peb);

/*
 * Validate segment permissions
 * Returns 1 if valid, 0 if invalid
 */
int peb_validate_perms(uint32_t perms);

/*
 * Register access for /proc filesystem
 * These functions allow accessing PEB registers without exposing the full structure
 */

/*
 * Format registers to string buffer
 * Returns number of characters written (excluding null terminator)
 */
int peb_format_regs(const PEB *peb, char *buf, size_t buf_size);

/*
 * Get register value by name
 * Returns value on success, 0 if register name not found
 */
uint64_t peb_get_reg(const PEB *peb, const char *reg_name);

/*
 * Set register value by name
 * Returns 0 on success, -1 if register name not found
 */
int peb_set_reg(PEB *peb, const char *reg_name, uint64_t value);

#endif /* PEB_H */
