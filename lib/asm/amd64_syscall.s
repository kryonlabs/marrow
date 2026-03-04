/*
 * AMD64 Syscall Gateway Assembly Stub
 * for Plan 9 Assembly Support in Marrow
 *
 * This stub is called when a patched SYSCALL instruction is executed.
 * It saves all registers, calls the C gateway handler, and restores.
 *
 * Calling convention:
 * - AX = syscall number (Plan 9 convention)
 * - DI, SI, DX, R10, R8, R9 = syscall arguments (System V convention)
 * - R15 = pointer to PEB (set by amd64_enter_plan9)
 *
 * Plan 9 assembly syntax
 */

/*
 * p9sys_gateway_stub - Syscall gateway entry point
 *
 * This function is called from patched SYSCALL instructions.
 * It must save all registers, call the C handler, and restore.
 *
 * Input:
 *   AX = syscall number
 *   DI, SI, DX, R10, R8, R9 = syscall arguments
 *   R15 = pointer to PEB (with regs pointing to Ureg)
 *
 * Output:
 *   AX = syscall return value
 */
GLOBL p9sys_gateway_stub(SB), $0
TEXT p9sys_gateway_stub(SB), $0
    /* Save all registers to the stack */
    /* We need to save the Plan 9 calling convention registers */
    PUSHQ AX          /* Syscall number */
    PUSHQ BX
    PUSHQ CX
    PUSHQ DX
    PUSHQ SI
    PUSHQ DI
    PUSHQ BP
    PUSHQ R8
    PUSHQ R9
    PUSHQ R10
    PUSHQ R11
    PUSHQ R12
    PUSHQ R13
    PUSHQ R14
    PUSHQ R15

    /* Save stack pointer for debugging */
    MOVQ SP, BP

    /* Setup arguments for C function call */
    /* int64_t p9sys_gateway(PEB *peb, int syscall_num, uint64_t *args) */

    /* DI = PEB pointer */
    /* R15 points to Ureg, we need to get PEB pointer */
    /* Ureg is at offset 136 in PEB */
    MOVQ R15, DI
    SUBQ $136, DI     /* PEB = &Ureg - offset */

    /* SI = syscall number */
    MOVQ 0(SP), SI   /* Get saved RAX from stack */

    /* DX = pointer to arguments array */
    /* Arguments are in DI, SI, DX, R10, R8, R9 */
    /* But we've saved them on the stack */
    /* Point to saved registers on stack */
    LEAQ 48(SP), DX  /* Skip RAX, RBX, RCX, RDX, RSI, RDI */

    /* Align stack to 16 bytes */
    ANDQ $-16, SP

    /* Make stack space for arguments array */
    SUBQ $64, SP

    /* Copy arguments from saved registers to array */
    /* Order: RDI, RSI, RDX, R10, R8, R9 */
    MOVQ 48(BP), AX   /* Saved RDI */
    MOVQ AX, 0(SP)
    MOVQ 56(BP), AX   /* Saved RSI */
    MOVQ AX, 8(SP)
    MOVQ 64(BP), AX   /* Saved RDX */
    MOVQ AX, 16(SP)
    MOVQ 104(BP), AX  /* Saved R10 */
    MOVQ AX, 24(SP)
    MOVQ 112(BP), AX  /* Saved R8 */
    MOVQ AX, 32(SP)
    MOVQ 120(BP), AX  /* Saved R9 */
    MOVQ AX, 40(SP)

    /* Pass array pointer as third argument */
    MOVQ SP, DX

    /* Call C gateway handler */
    CALL p9sys_gateway(SB)

    /* Restore stack pointer */
    MOVQ BP, SP

    /* Restore all registers */
    POPQ R15
    POPQ R14
    POPQ R13
    POPQ R12
    POPQ R11
    POPQ R10
    POPQ R9
    POPQ R8
    POPQ BP
    POPQ DI
    POPQ SI
    POPQ DX
    POPQ CX
    POPQ BX

    /* Restore syscall return value to RAX */
    /* The C function returns in RAX, which is on top of stack */
    ADDQ $8, SP        /* Skip saved RAX */
    PUSHQ AX           /* Push return value */

    /* Restore RAX with return value */
    POPQ AX

    /* Return to caller */
    RET

/*
 * Alternative simpler version
 * Just save registers and call C handler directly
 */
GLOBL p9sys_gateway_stub_simple(SB), $0
TEXT p9sys_gateway_stub_simple(SB), $0
    /* Save all registers */
    PUSHQ AX
    PUSHQ BX
    PUSHQ CX
    PUSHQ DX
    PUSHQ SI
    PUSHQ DI
    PUSHQ BP
    PUSHQ R8
    PUSHQ R9
    PUSHQ R10
    PUSHQ R11
    PUSHQ R12
    PUSHQ R13
    PUSHQ R14
    PUSHQ R15

    /* Save RSP */
    MOVQ SP, R11

    /* R15 points to Ureg, get PEB pointer */
    MOVQ R15, DI
    SUBQ $136, DI

    /* Syscall number is on stack (first push) */
    MOVQ 120(R11), SI

    /* Create args array on stack */
    SUBQ $64, SP
    ANDQ $-16, SP

    /* Copy argument registers to array */
    /* Original args before syscall were in RDI, RSI, RDX, RCX, R8, R9 */
    /* But Plan 9 uses RDI, RSI, RDX, R10, R8, R9 */
    /* System V uses RDI, RSI, RDX, RCX, R8, R9 */
    /* So we need to handle this properly */

    /* For now, just use the register values */
    MOVQ 104(R11), AX  /* Saved RDI */
    MOVQ AX, (SP)
    MOVQ 96(R11), AX   /* Saved RSI */
    MOVQ AX, 8(SP)
    MOVQ 88(R11), AX   /* Saved RDX */
    MOVQ AX, 16(SP)
    MOVQ 56(R11), AX   /* Saved R10 */
    MOVQ AX, 24(SP)
    MOVQ 48(R11), AX   /* Saved R8 */
    MOVQ AX, 32(SP)
    MOVQ 40(R11), AX   /* Saved R9 */
    MOVQ AX, 40(SP)

    MOVQ SP, DX        /* Third arg: args array */

    /* Call C handler */
    CALL p9sys_gateway(SB)

    /* Restore stack */
    MOVQ R11, SP
    ADDQ $64, SP

    /* Restore registers (except RAX which has return value) */
    ADDQ $8, SP          /* Skip saved RAX */
    POPQ BX
    POPQ CX
    POPQ DX
    POPQ SI
    POPQ DI
    POPQ BP
    POPQ R8
    POPQ R9
    POPQ R10
    POPQ R11
    POPQ R12
    POPQ R13
    POPQ R14
    POPQ R15

    /* RAX already has return value from C function */
    RET
