/*
 * Process Environment Block Implementation
 * C89/C90 compliant
 *
 * Implements the Process Environment Block (PEB) for tracking
 * Plan 9 process execution state within Marrow.
 */

#include "runtime/peb.h"
#include "p9/p9compat.h"
#include <lib9.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/*
 * Initial symbol table capacity
 */
#define INITIAL_SYMBOL_CAPACITY 128

/*
 * strdup implementation for C89 compliance
 */
static char *p9_strdup(const char *s)
{
    char *copy;
    size_t len;

    if (s == NULL) {
        return NULL;
    }

    len = strlen(s) + 1;
    copy = (char *)malloc(len);
    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, s, len);
    return copy;
}

/*
 * Create a new Process Environment Block
 */
PEB *peb_create(void)
{
    PEB *peb;

    peb = (PEB *)malloc(sizeof(PEB));
    if (peb == NULL) {
        fprintf(stderr, "peb_create: malloc failed\n");
        return NULL;
    }

    /* Zero-initialize all fields */
    memset(peb, 0, sizeof(PEB));

    /* Initialize identification */
    peb->pid = 0;
    peb->cmd[0] = '\0';
    peb->active = 0;

    /* Initialize segments */
    peb->text.base = NULL;
    peb->text.size = 0;
    peb->text.perms = 0;

    peb->data.base = NULL;
    peb->data.size = 0;
    peb->data.perms = 0;

    peb->bss.base = NULL;
    peb->bss.size = 0;
    peb->bss.perms = 0;

    peb->stack.base = NULL;
    peb->stack.size = 0;
    peb->stack.perms = 0;

    /* Allocate symbol table */
    peb->symbol_capacity = INITIAL_SYMBOL_CAPACITY;
    peb->symbols = (P9Symbol *)malloc(sizeof(P9Symbol) * peb->symbol_capacity);
    if (peb->symbols == NULL) {
        fprintf(stderr, "peb_create: symbol table malloc failed\n");
        free(peb);
        return NULL;
    }
    peb->nsymbols = 0;

    /* Initialize registers */
    memset(&peb->regs, 0, sizeof(P9Ureg));

    /* Initialize state */
    peb->state = P9_STATE_READY;
    peb->exit_status = 0;

    /* Initialize file descriptor table */
    memset(peb->fds, 0, sizeof(peb->fds));

    /* Initialize syscall gateway */
    peb->syscall_gateway = NULL;

    /* Initialize entry point */
    peb->entry = 0;

    /* Initialize current working directory */
    peb->cwd[0] = '/';
    peb->cwd[1] = '\0';

    /* Initialize note system */
    peb->notify_fn = NULL;
    peb->pending_note[0] = '\0';
    peb->note_pending = 0;

    /* Initialize rfork flags */
    peb->rfork_flags = 0;

    /* Initialize rendezvous state */
    peb->rend_tag = 0;
    peb->rend_state = 0;

    /* Initialize _tos (timing data) */
    peb->tos.pcycles = 0;
    peb->tos.cyclefreq = p9_cpufreq();

    /* Initialize attached segments */
    memset(peb->attached_segs, 0, sizeof(peb->attached_segs));

    return peb;
}

/*
 * Destroy a PEB and free all associated memory
 */
void peb_destroy(PEB *peb)
{
    int i;

    if (peb == NULL) {
        return;
    }

    /* Free text segment */
    if (peb->text.base != NULL) {
        munmap(peb->text.base, peb->text.size);
    }

    /* Free data segment */
    if (peb->data.base != NULL) {
        munmap(peb->data.base, peb->data.size);
    }

    /* Free BSS segment */
    if (peb->bss.base != NULL) {
        munmap(peb->bss.base, peb->bss.size);
    }

    /* Free stack segment */
    if (peb->stack.base != NULL) {
        munmap(peb->stack.base, peb->stack.size);
    }

    /* Free symbol table */
    if (peb->symbols != NULL) {
        /* Free symbol names */
        for (i = 0; i < peb->nsymbols; i++) {
            if (peb->symbols[i].name != NULL) {
                free(peb->symbols[i].name);
            }
        }
        free(peb->symbols);
    }

    /* Free PEB itself */
    free(peb);
}

/*
 * Validate segment permissions
 */
int peb_validate_perms(uint32_t perms)
{
    /* Check for valid permission combinations */
    if (perms == 0) {
        return 0;  /* No permissions is invalid */
    }

    /* Basic permissions are valid */
    if ((perms & ~(P9_PERM_READ | P9_PERM_WRITE | P9_PERM_EXEC)) != 0) {
        return 0;  /* Unknown permission flags */
    }

    return 1;
}

/*
 * Allocate a memory segment with specified permissions
 */
int peb_alloc_segment(PEB *peb, P9Segment *seg, uint32_t size, uint32_t perms)
{
    void *addr;
    int prot;

    if (peb == NULL || seg == NULL) {
        fprintf(stderr, "peb_alloc_segment: NULL argument\n");
        return -1;
    }

    if (size == 0) {
        fprintf(stderr, "peb_alloc_segment: zero size\n");
        return -1;
    }

    if (!peb_validate_perms(perms)) {
        fprintf(stderr, "peb_alloc_segment: invalid permissions 0x%x\n", perms);
        return -1;
    }

    /* Calculate mmap protection flags */
    prot = 0;
    if (perms & P9_PERM_READ)  prot |= PROT_READ;
    if (perms & P9_PERM_WRITE) prot |= PROT_WRITE;
    if (perms & P9_PERM_EXEC)  prot |= PROT_EXEC;

    /* Round up to page size */
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    /* Allocate memory */
    addr = mmap(NULL, size,
                prot | PROT_WRITE,  /* Need write for initialization */
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0);

    if (addr == MAP_FAILED) {
        perror("peb_alloc_segment: mmap failed");
        return -1;
    }

    /* Initialize to zero */
    memset(addr, 0, size);

    /* Remove write permission if not requested */
    if (!(perms & P9_PERM_WRITE)) {
        if (mprotect(addr, size, prot) < 0) {
            perror("peb_alloc_segment: mprotect failed");
            munmap(addr, size);
            return -1;
        }
    }

    /* Set segment fields */
    seg->base = (uint8_t *)addr;
    seg->size = size;
    seg->perms = perms;

    return 0;
}

/*
 * Setup stack with guard pages
 */
int peb_setup_stack(PEB *peb, uint32_t stack_size)
{
    void *stack_top;
    uint8_t *stack_base;
    int total_size;

    if (peb == NULL) {
        fprintf(stderr, "peb_setup_stack: NULL argument\n");
        return -1;
    }

    if (stack_size < PAGE_SIZE * 2) {
        fprintf(stderr, "peb_setup_stack: stack too small\n");
        return -1;
    }

    /* Round up to page size and add guard page */
    stack_size = (stack_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    total_size = stack_size + PAGE_SIZE;  /* Extra guard page */

    /* Allocate stack with guard page at bottom */
    stack_base = (uint8_t *)mmap(NULL, total_size,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS,
                                -1, 0);

    if (stack_base == MAP_FAILED) {
        perror("peb_setup_stack: mmap failed");
        return -1;
    }

    /* Make guard page inaccessible (at bottom of stack) */
    if (mprotect(stack_base, PAGE_SIZE, PROT_NONE) < 0) {
        perror("peb_setup_stack: mprotect guard page failed");
        munmap(stack_base, total_size);
        return -1;
    }

    /* Stack grows down, so top is after guard page */
    peb->stack.base = stack_base + PAGE_SIZE;
    peb->stack.size = stack_size;
    peb->stack.perms = P9_PERM_READ | P9_PERM_WRITE;

    /* Set initial stack pointer (stack grows down) */
    stack_top = stack_base + PAGE_SIZE + stack_size;
    peb->regs.sp = (uint64_t)stack_top;

    return 0;
}

/*
 * Add a symbol to the symbol table
 */
int peb_add_symbol(PEB *peb, const char *name, uint64_t value, uint8_t type)
{
    P9Symbol *sym;
    char *name_copy;

    if (peb == NULL || name == NULL) {
        fprintf(stderr, "peb_add_symbol: NULL argument\n");
        return -1;
    }

    /* Expand symbol table if needed */
    if (peb->nsymbols >= peb->symbol_capacity) {
        int new_capacity;
        P9Symbol *new_symbols;

        new_capacity = peb->symbol_capacity * 2;
        new_symbols = (P9Symbol *)realloc(peb->symbols,
                                         sizeof(P9Symbol) * new_capacity);
        if (new_symbols == NULL) {
            fprintf(stderr, "peb_add_symbol: realloc failed\n");
            return -1;
        }

        peb->symbols = new_symbols;
        peb->symbol_capacity = new_capacity;
    }

    /* Copy symbol name */
    name_copy = p9_strdup(name);
    if (name_copy == NULL) {
        fprintf(stderr, "peb_add_symbol: p9_strdup failed\n");
        return -1;
    }

    /* Add symbol */
    sym = &peb->symbols[peb->nsymbols];
    sym->name = name_copy;
    sym->value = value;
    sym->type = type;

    peb->nsymbols++;

    return 0;
}

/*
 * Find a symbol by name (linear search)
 */
P9Symbol *peb_find_symbol(PEB *peb, const char *name)
{
    int i;

    if (peb == NULL || name == NULL) {
        return NULL;
    }

    for (i = 0; i < peb->nsymbols; i++) {
        if (strcmp(peb->symbols[i].name, name) == 0) {
            return &peb->symbols[i];
        }
    }

    return NULL;
}

/*
 * Sort symbols by name (using simple bubble sort for C89)
 */
void peb_sort_symbols(PEB *peb)
{
    int i, j;
    P9Symbol temp;

    if (peb == NULL || peb->symbols == NULL) {
        return;
    }

    /* Simple bubble sort - acceptable for small symbol tables */
    for (i = 0; i < peb->nsymbols - 1; i++) {
        for (j = 0; j < peb->nsymbols - i - 1; j++) {
            if (strcmp(peb->symbols[j].name, peb->symbols[j + 1].name) > 0) {
                /* Swap symbols */
                temp = peb->symbols[j];
                peb->symbols[j] = peb->symbols[j + 1];
                peb->symbols[j + 1] = temp;
            }
        }
    }
}

/*
 * Allocate a new file descriptor
 */
int peb_alloc_fd(PEB *peb)
{
    int i;

    if (peb == NULL) {
        return -1;
    }

    /* Find free fd */
    for (i = 0; i < P9_MAX_FDS; i++) {
        if (!peb->fds[i].is_active) {
            peb->fds[i].is_active = 1;
            peb->fds[i].node_ptr = NULL;
            peb->fds[i].mode = 0;
            peb->fds[i].offset = 0;
            peb->fds[i].host_fd = -1;
            return i;
        }
    }

    fprintf(stderr, "peb_alloc_fd: no free fd slots\n");
    return -1;
}

/*
 * Close a file descriptor
 */
int peb_close_fd(PEB *peb, int fd)
{
    if (peb == NULL) {
        return -1;
    }

    if (fd < 0 || fd >= P9_MAX_FDS) {
        fprintf(stderr, "peb_close_fd: invalid fd %d\n", fd);
        return -1;
    }

    if (!peb->fds[fd].is_active) {
        fprintf(stderr, "peb_close_fd: fd %d not active\n", fd);
        return -1;
    }

    /* Close host pipe fd if present */
    if (peb->fds[fd].host_fd >= 0) {
        close(peb->fds[fd].host_fd);
    }

    peb->fds[fd].is_active = 0;
    peb->fds[fd].node_ptr = NULL;
    peb->fds[fd].mode = 0;
    peb->fds[fd].offset = 0;
    peb->fds[fd].host_fd = -1;

    return 0;
}

/*
 * Get file descriptor entry
 */
P9FdEntry *peb_get_fd(PEB *peb, int fd)
{
    if (peb == NULL) {
        return NULL;
    }

    if (fd < 0 || fd >= P9_MAX_FDS) {
        return NULL;
    }

    if (!peb->fds[fd].is_active) {
        return NULL;
    }

    return &peb->fds[fd];
}

/*
 * Print PEB information for debugging
 */
void peb_print_info(PEB *peb)
{
    int i;

    if (peb == NULL) {
        printf("PEB: NULL\n");
        return;
    }

    printf("=== Process Environment Block ===\n");
    printf("PID: %d\n", peb->pid);
    printf("Command: %s\n", peb->cmd);
    printf("Active: %d\n", peb->active);
    printf("State: %d\n", peb->state);
    printf("Entry: 0x%llx\n", (unsigned long long)peb->entry);
    printf("\n");

    printf("Segments:\n");
    printf("  Text: base=%p size=%u perms=0x%x\n",
           (void *)peb->text.base, peb->text.size, peb->text.perms);
    printf("  Data: base=%p size=%u perms=0x%x\n",
           (void *)peb->data.base, peb->data.size, peb->data.perms);
    printf("  BSS:  base=%p size=%u perms=0x%x\n",
           (void *)peb->bss.base, peb->bss.size, peb->bss.perms);
    printf("  Stack: base=%p size=%u perms=0x%x\n",
           (void *)peb->stack.base, peb->stack.size, peb->stack.perms);
    printf("\n");

    printf("Registers:\n");
    printf("  RIP=0x%016llx RSP=0x%016llx RFLAGS=0x%016llx\n",
           (unsigned long long)peb->regs.ip,
           (unsigned long long)peb->regs.sp,
           (unsigned long long)peb->regs.flags);
    printf("  RAX=0x%016llx RBX=0x%016llx RCX=0x%016llx RDX=0x%016llx\n",
           (unsigned long long)peb->regs.ax,
           (unsigned long long)peb->regs.bx,
           (unsigned long long)peb->regs.cx,
           (unsigned long long)peb->regs.dx);
    printf("  RSI=0x%016llx RDI=0x%016llx RBP=0x%016llx R15=0x%016llx\n",
           (unsigned long long)peb->regs.si,
           (unsigned long long)peb->regs.di,
           (unsigned long long)peb->regs.bp,
           (unsigned long long)peb->regs.r15);
    printf("\n");

    printf("Symbols: %d entries (showing first 10)\n", peb->nsymbols);
    for (i = 0; i < peb->nsymbols && i < 10; i++) {
        printf("  %s: value=0x%llx type=%c\n",
               peb->symbols[i].name,
               (unsigned long long)peb->symbols[i].value,
               peb->symbols[i].type);
    }
    printf("\n");
}

/*
 * Format registers to string buffer
 * For use by /proc filesystem
 */
int peb_format_regs(const PEB *peb, char *buf, size_t buf_size)
{
    int len;

    if (peb == NULL || buf == NULL || buf_size == 0) {
        return 0;
    }

    /* Format each register on a separate line */
    len = snprint(buf, buf_size,
                  "AX   %016lx\n"
                  "BX   %016lx\n"
                  "CX   %016lx\n"
                  "DX   %016lx\n"
                  "SI   %016lx\n"
                  "DI   %016lx\n"
                  "BP   %016lx\n"
                  "R8   %016lx\n"
                  "R9   %016lx\n"
                  "R10  %016lx\n"
                  "R11  %016lx\n"
                  "R12  %016lx\n"
                  "R13  %016lx\n"
                  "R14  %016lx\n"
                  "R15   %016lx\n"
                  "IP   %016lx\n"
                  "FLAGS %016lx\n"
                  "SP   %016lx\n",
                  (unsigned long)peb->regs.ax,
                  (unsigned long)peb->regs.bx,
                  (unsigned long)peb->regs.cx,
                  (unsigned long)peb->regs.dx,
                  (unsigned long)peb->regs.si,
                  (unsigned long)peb->regs.di,
                  (unsigned long)peb->regs.bp,
                  (unsigned long)peb->regs.r8,
                  (unsigned long)peb->regs.r9,
                  (unsigned long)peb->regs.r10,
                  (unsigned long)peb->regs.r11,
                  (unsigned long)peb->regs.r12,
                  (unsigned long)peb->regs.r13,
                  (unsigned long)peb->regs.r14,
                  (unsigned long)peb->regs.r15,
                  (unsigned long)peb->regs.ip,
                  (unsigned long)peb->regs.flags,
                  (unsigned long)peb->regs.sp
    );

    return len;
}

/*
 * Get register value by name
 */
uint64_t peb_get_reg(const PEB *peb, const char *reg_name)
{
    if (peb == NULL || reg_name == NULL) {
        return 0;
    }

    if (strcmp(reg_name, "AX") == 0 || strcmp(reg_name, "RAX") == 0)
        return peb->regs.ax;
    if (strcmp(reg_name, "BX") == 0 || strcmp(reg_name, "RBX") == 0)
        return peb->regs.bx;
    if (strcmp(reg_name, "CX") == 0 || strcmp(reg_name, "RCX") == 0)
        return peb->regs.cx;
    if (strcmp(reg_name, "DX") == 0 || strcmp(reg_name, "RDX") == 0)
        return peb->regs.dx;
    if (strcmp(reg_name, "SI") == 0 || strcmp(reg_name, "RSI") == 0)
        return peb->regs.si;
    if (strcmp(reg_name, "DI") == 0 || strcmp(reg_name, "RDI") == 0)
        return peb->regs.di;
    if (strcmp(reg_name, "BP") == 0 || strcmp(reg_name, "RBP") == 0)
        return peb->regs.bp;
    if (strcmp(reg_name, "R8") == 0)
        return peb->regs.r8;
    if (strcmp(reg_name, "R9") == 0)
        return peb->regs.r9;
    if (strcmp(reg_name, "R10") == 0)
        return peb->regs.r10;
    if (strcmp(reg_name, "R11") == 0)
        return peb->regs.r11;
    if (strcmp(reg_name, "R12") == 0)
        return peb->regs.r12;
    if (strcmp(reg_name, "R13") == 0)
        return peb->regs.r13;
    if (strcmp(reg_name, "R14") == 0)
        return peb->regs.r14;
    if (strcmp(reg_name, "R15") == 0)
        return peb->regs.r15;
    if (strcmp(reg_name, "IP") == 0 || strcmp(reg_name, "RIP") == 0)
        return peb->regs.ip;
    if (strcmp(reg_name, "FLAGS") == 0 || strcmp(reg_name, "RFLAGS") == 0)
        return peb->regs.flags;
    if (strcmp(reg_name, "SP") == 0 || strcmp(reg_name, "RSP") == 0)
        return peb->regs.sp;

    return 0;
}

/*
 * Set register value by name
 */
int peb_set_reg(PEB *peb, const char *reg_name, uint64_t value)
{
    if (peb == NULL || reg_name == NULL) {
        return -1;
    }

    if (strcmp(reg_name, "AX") == 0 || strcmp(reg_name, "RAX") == 0) {
        peb->regs.ax = value;
        return 0;
    }
    if (strcmp(reg_name, "BX") == 0 || strcmp(reg_name, "RBX") == 0) {
        peb->regs.bx = value;
        return 0;
    }
    if (strcmp(reg_name, "CX") == 0 || strcmp(reg_name, "RCX") == 0) {
        peb->regs.cx = value;
        return 0;
    }
    if (strcmp(reg_name, "DX") == 0 || strcmp(reg_name, "RDX") == 0) {
        peb->regs.dx = value;
        return 0;
    }
    if (strcmp(reg_name, "SI") == 0 || strcmp(reg_name, "RSI") == 0) {
        peb->regs.si = value;
        return 0;
    }
    if (strcmp(reg_name, "DI") == 0 || strcmp(reg_name, "RDI") == 0) {
        peb->regs.di = value;
        return 0;
    }
    if (strcmp(reg_name, "BP") == 0 || strcmp(reg_name, "RBP") == 0) {
        peb->regs.bp = value;
        return 0;
    }
    if (strcmp(reg_name, "R8") == 0) {
        peb->regs.r8 = value;
        return 0;
    }
    if (strcmp(reg_name, "R9") == 0) {
        peb->regs.r9 = value;
        return 0;
    }
    if (strcmp(reg_name, "R10") == 0) {
        peb->regs.r10 = value;
        return 0;
    }
    if (strcmp(reg_name, "R11") == 0) {
        peb->regs.r11 = value;
        return 0;
    }
    if (strcmp(reg_name, "R12") == 0) {
        peb->regs.r12 = value;
        return 0;
    }
    if (strcmp(reg_name, "R13") == 0) {
        peb->regs.r13 = value;
        return 0;
    }
    if (strcmp(reg_name, "R14") == 0) {
        peb->regs.r14 = value;
        return 0;
    }
    if (strcmp(reg_name, "R15") == 0) {
        peb->regs.r15 = value;
        return 0;
    }
    if (strcmp(reg_name, "IP") == 0 || strcmp(reg_name, "RIP") == 0) {
        peb->regs.ip = value;
        return 0;
    }
    if (strcmp(reg_name, "FLAGS") == 0 || strcmp(reg_name, "RFLAGS") == 0) {
        peb->regs.flags = value;
        return 0;
    }
    if (strcmp(reg_name, "SP") == 0 || strcmp(reg_name, "RSP") == 0) {
        peb->regs.sp = value;
        return 0;
    }

    return -1;
}
