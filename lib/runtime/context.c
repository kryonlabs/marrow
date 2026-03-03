/*
 * Plan 9 Context Switching Implementation
 * C89/C90 compliant
 *
 * Handles switching between host OS (Linux/System V AMD64)
 * and Plan 9 calling conventions.
 */

#include "runtime/context.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * Initialize context switching module
 */
int context_init(void)
{
    /* Nothing to initialize currently */
    return 0;
}

/*
 * Cleanup context switching module
 */
void context_cleanup(void)
{
    /* Nothing to cleanup currently */
}

/*
 * Save current host context
 */
int context_save_host(ContextFrame *ctx)
{
    if (ctx == NULL) {
        fprintf(stderr, "context_save_host: NULL context\n");
        return -1;
    }

    /* Call assembly stub to save all registers */
    return amd64_save_context(ctx);
}

/*
 * Restore host context
 */
int context_restore_host(const ContextFrame *ctx)
{
    if (ctx == NULL) {
        fprintf(stderr, "context_restore_host: NULL context\n");
        return -1;
    }

    /* Call assembly stub to restore all registers */
    return amd64_restore_context(ctx);
}

/*
 * Enter Plan 9 execution mode
 */
int context_enter_plan9(PEB *peb)
{
    if (peb == NULL) {
        fprintf(stderr, "context_enter_plan9: NULL peb\n");
        return -1;
    }

    if (peb->entry == 0) {
        fprintf(stderr, "context_enter_plan9: no entry point\n");
        return -1;
    }

    /* Mark as running */
    peb->state = P9_STATE_RUNNING;

    /* Call assembly stub to enter Plan 9 mode */
    /* This function does NOT return */
    amd64_enter_plan9(peb);

    /* Should never reach here */
    fprintf(stderr, "context_enter_plan9: returned from Plan 9 execution\n");
    return -1;
}

/*
 * Execute a Plan 9 function with given arguments
 *
 * This is a helper for testing and debugging.
 * Note: This is a simplified version that doesn't do full context switching.
 * For production use, you'd need a more sophisticated mechanism.
 */
uint64_t context_call_plan9(PEB *peb, uint64_t func_addr,
                            const uint64_t *args, int nargs)
{
    ContextFrame host_ctx;
    uint64_t result;
    int i;

    if (peb == NULL || func_addr == 0) {
        fprintf(stderr, "context_call_plan9: NULL peb or invalid address\n");
        return 0;
    }

    /* Save host context */
    if (context_save_host(&host_ctx) < 0) {
        fprintf(stderr, "context_call_plan9: save host failed\n");
        return 0;
    }

    /* Setup Plan 9 registers */
    peb->regs.ip = func_addr;

    /* Setup arguments (System V AMD64 calling convention) */
    /* RDI, RSI, RDX, RCX, R8, R9 */
    if (args != NULL && nargs > 0) {
        peb->regs.di = (nargs > 0) ? args[0] : 0;
        peb->regs.si = (nargs > 1) ? args[1] : 0;
        peb->regs.dx = (nargs > 2) ? args[2] : 0;
        peb->regs.cx = (nargs > 3) ? args[3] : 0;
        peb->regs.r8 = (nargs > 4) ? args[4] : 0;
        peb->regs.r9 = (nargs > 5) ? args[5] : 0;
    }

    /* CRITICAL: Set R15 to point to Ureg */
    /* This is required by Plan 9's syscall convention */
    peb->regs.r15 = (uint64_t)&peb->regs;

    /* Enter Plan 9 mode */
    /* Note: This is a simplified version */
    /* In reality, we'd need to handle stack setup and return properly */
    amd64_enter_plan9(peb);

    /* Restore host context */
    if (context_restore_host(&host_ctx) < 0) {
        fprintf(stderr, "context_call_plan9: restore host failed\n");
        return 0;
    }

    /* Return value is in RAX */
    result = peb->regs.ax;

    return result;
}

/*
 * Print context frame for debugging
 */
void context_print_frame(const ContextFrame *ctx)
{
    int i;

    if (ctx == NULL) {
        printf("Context: NULL\n");
        return;
    }

    printf("=== Host Context Frame ===\n");
    printf("Host Registers:\n");
    for (i = 0; i < 16; i++) {
        printf("  [%2d] = 0x%016llx\n", i,
               (unsigned long long)ctx->host_regs[i]);
    }
    printf("Host Flags: 0x%016llx\n", (unsigned long long)ctx->host_flags);
    printf("Host SP:    0x%016llx\n", (unsigned long long)ctx->host_sp);
    printf("Host BP:    0x%016llx\n", (unsigned long long)ctx->host_bp);
    printf("\n");
}
