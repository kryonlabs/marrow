#ifndef P9_UREG_H
#define P9_UREG_H

#include <stdint.h>

/*
 * Plan 9 Ureg Structure - 9front Compatible
 * Source: 9front amd64/include/ureg.h
 * Adapted for Marrow - Hosted Plan 9 Execution Environment
 *
 * This structure defines the complete CPU register state as used by
 * Plan 9 for trap handling and context switching.
 *
 * CRITICAL: In Plan 9 amd64, R15 MUST point to this Ureg structure!
 * This is how Plan 9 code finds its register save area during syscalls.
 *
 * Differences from 9front:
 * - Removed segment registers (ds, es, fs, gs) - not used in 64-bit mode
 * - Removed cs, ss - not needed in hosted environment
 * - Kept type and error for compatibility with 9front binaries
 * - Added convenience pointer to self
 */

struct Ureg {
    uint64_t ax;         /* RAX - syscall number / return value */
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
    uint64_t r15;        /* R15 - MUST point to this Ureg! */
    uint64_t type;       /* Trap type (0 = syscall) */
    uint64_t error;      /* Error code (0 = no error) */
    uint64_t pc;         /* Program counter (RIP) */
    uint64_t flags;      /* RFLAGS */
    uint64_t sp;         /* Stack pointer (RSP) */

    /*
     * Syscall arguments
     * In Plan 9 amd64 syscall convention:
     * - RAX = syscall number
     * - RDI, RSI, RDX, RCX, R8, R9 = arguments (max 6)
     * - Additional arguments on stack
     */
    uint64_t arg[6];     /* First 6 syscall arguments (from registers) */

    /* Convenience pointer to self */
    struct Ureg *ureg;   /* Pointer to this Ureg structure */
};

/*
 * Trap types for the type field
 */
#define P9_TRAP_SYSCALL   0   /* System call */
#define P9_TRAP_FAULT     1   /* Memory fault */
#define P9_TRAP_MATH      2   /* Math/coprocessor error */
#define P9_TRAP_ASYNC     3   /* Asynchronous trap/interrupt */

/*
 * Macros for accessing syscall arguments
 */
#define P9_SYSARG(ureg, n)  ((ureg)->arg[n])
#define P9_SYSNUM(ureg)     ((ureg)->ax)
#define P9_SYSRET(ureg)     ((ureg)->ax = (ureg)->ax)

#endif /* P9_UREG_H */
