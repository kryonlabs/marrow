#ifndef CONTEXT_H
#define CONTEXT_H

#include "runtime/peb.h"
#include <stdint.h>

/*
 * Plan 9 Context Switching
 * C89/C90 compliant
 *
 * This module handles switching between host OS (Linux/System V AMD64)
 * and Plan 9 calling conventions.
 */

/*
 * Context frame for saving host state
 * When switching from host to Plan 9, we save all host registers here.
 */
typedef struct {
    uint64_t host_regs[16];  /* RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP */
                             /* R8, R9, R10, R11, R12, R13, R14, R15 */
    uint64_t host_flags;     /* RFLAGS */
    uint64_t host_sp;        /* RSP */
    uint64_t host_bp;        /* RBP */
} ContextFrame;

/*
 * Context switching API
 */

/*
 * Initialize context switching module
 * Returns 0 on success, -1 on error
 */
int context_init(void);

/*
 * Cleanup context switching module
 */
void context_cleanup(void);

/*
 * Enter Plan 9 execution mode
 *
 * This function:
 * 1. Sets R15 to point to the Ureg structure (Plan 9 requirement!)
 * 2. Loads Plan 9 registers from PEB.regs
 * 3. Jumps to the entry point
 *
 * CRITICAL: In Plan 9 amd64, R15 MUST point to Ureg structure!
 * This is how Plan 9 code finds its register save area during syscalls.
 *
 * Parameters:
 *   peb - PEB with initialized registers and entry point
 *
 * This function does NOT return normally.
 * Returns only on error.
 */
int context_enter_plan9(PEB *peb);

/*
 * Save current host context
 *
 * Saves all host registers and flags into the context frame.
 * Used when switching from host to Plan 9 execution.
 *
 * Parameters:
 *   ctx - Context frame to save into
 *
 * Returns 0 on success, -1 on error
 */
int context_save_host(ContextFrame *ctx);

/*
 * Restore host context
 *
 * Restores all host registers and flags from the context frame.
 * Used when returning from Plan 9 to host execution.
 *
 * Parameters:
 *   ctx - Context frame to restore from
 *
 * Returns 0 on success, -1 on error
 */
int context_restore_host(const ContextFrame *ctx);

/*
 * Execute a Plan 9 function with given arguments
 *
 * This is a helper for testing and debugging.
 * It switches to Plan 9 mode, calls a function, and returns.
 *
 * Parameters:
 *   peb       - PEB with execution context
 *   func_addr - Address of function to call
 *   args      - Array of up to 6 arguments (for RDI, RSI, RDX, RCX, R8, R9)
 *   nargs     - Number of arguments
 *
 * Returns the function's return value in RAX
 */
uint64_t context_call_plan9(PEB *peb, uint64_t func_addr,
                            const uint64_t *args, int nargs);

/*
 * Assembly functions (implemented in amd64_ctx.S)
 */

/*
 * Save all host registers to context frame
 * Implemented in assembly for complete register preservation
 */
extern int amd64_save_context(ContextFrame *ctx);

/*
 * Restore all host registers from context frame
 * Implemented in assembly for complete register restoration
 */
extern int amd64_restore_context(const ContextFrame *ctx);

/*
 * Enter Plan 9 execution mode
 *
 * Assembly stub that:
 * 1. Sets R15 = &PEB.regs (CRITICAL for Plan 9!)
 * 2. Loads all registers from PEB.regs
 * 3. Jumps to PEB.regs.ip
 *
 * Parameters:
 *   peb - PEB pointer (in RDI per System V calling convention)
 *
 * Implemented in amd64_ctx.S
 */
extern void amd64_enter_plan9(PEB *peb);

#endif /* CONTEXT_H */
