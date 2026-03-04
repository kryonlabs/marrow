/*
 * AMD64 Context Switching Assembly Stubs
 * for Plan 9 Assembly Support in Marrow
 *
 * This file contains the low-level assembly routines for
 * switching between System V AMD64 (Linux) and Plan 9 calling conventions.
 *
 * CRITICAL: In Plan 9 amd64, R15 MUST point to the Ureg structure!
 * This is how Plan 9 code finds its register save area during syscalls.
 *
 * Plan 9 assembly syntax:
 * - GLOBL instead of .global
 * - TEXT entry, $framesize
 * - Register names without % prefix
 * - MOVQ instead of movq
 * - Destination on left (like Intel syntax)
 * - No .type or .size directives
 */

/*
 * amd64_save_context - Save all host registers
 *
 * Input:  DI = pointer to ContextFrame
 * Output: AX = 0 on success, -1 on error
 * Clobbers: AX, CX, DX
 */
GLOBL amd64_save_context(SB), $0
TEXT amd64_save_context(SB), $0
    /* Check for NULL pointer */
    TESTQ DI, DI
    JEQ .save_error

    /* Save RAX first (since we're using it) */
    MOVQ AX, (DI)

    /* Save all registers to context frame */
    MOVQ BX, 8(DI)
    MOVQ CX, 16(DI)
    MOVQ DX, 24(DI)
    MOVQ SI, 32(DI)
    MOVQ DI, 40(DI)      /* Save original RDI */
    MOVQ BP, 48(DI)
    MOVQ SP, 56(DI)
    MOVQ R8,  64(DI)
    MOVQ R9,  72(DI)
    MOVQ R10, 80(DI)
    MOVQ R11, 88(DI)
    MOVQ R12, 96(DI)
    MOVQ R13, 104(DI)
    MOVQ R14, 112(DI)
    MOVQ R15, 120(DI)

    /* Save RFLAGS */
    PUSHFQ
    POPQ AX
    MOVQ AX, 128(DI)

    /* Save RSP and RBP separately */
    MOVQ SP, 136(DI)
    MOVQ BP, 144(DI)

    /* Return success */
    XORQ AX, AX
    RET

.save_error:
    MOVQ $-1, AX
    RET

/*
 * amd64_restore_context - Restore all host registers
 *
 * Input:  DI = pointer to ContextFrame
 * Output: AX = 0 on success, -1 on error
 * Clobbers: CX, DX
 */
GLOBL amd64_restore_context(SB), $0
TEXT amd64_restore_context(SB), $0
    /* Check for NULL pointer */
    TESTQ DI, DI
    JEQ .restore_error

    /* Restore all registers from context frame */
    MOVQ (DI), AX
    MOVQ 8(DI), BX
    MOVQ 16(DI), CX
    MOVQ 24(DI), DX
    MOVQ 32(DI), SI
    MOVQ 40(DI), BP      /* We'll restore RDI last */
    MOVQ 48(DI), BP
    MOVQ 56(DI), SP
    MOVQ 64(DI), R8
    MOVQ 72(DI), R9
    MOVQ 80(DI), R10
    MOVQ 88(DI), R11
    MOVQ 96(DI), R12
    MOVQ 104(DI), R13
    MOVQ 112(DI), R14
    MOVQ 120(DI), R15

    /* Restore RFLAGS */
    MOVQ 128(DI), AX
    PUSHQ AX
    POPFQ

    /* Restore RSP and RBP */
    MOVQ 136(DI), SP
    MOVQ 144(DI), BP

    /* Restore RDI last (it's our pointer to the context frame) */
    MOVQ 40(DI), DI

    /* Return success */
    XORQ AX, AX
    RET

.restore_error:
    MOVQ $-1, AX
    RET

/*
 * amd64_enter_plan9 - Enter Plan 9 execution mode
 *
 * CRITICAL: This function MUST set R15 to point to the Ureg structure!
 * Plan 9 code expects R15 to always point to its register save area.
 *
 * Input:  DI = pointer to PEB
 * Output: Does not return (jumps to Plan 9 entry point)
 */
GLOBL amd64_enter_plan9(SB), $0
TEXT amd64_enter_plan9(SB), $0
    /* Check for NULL pointer */
    TESTQ DI, DI
    JEQ .enter_error

    /* Save callee-saved registers (we'll need these after Plan 9 returns) */
    PUSHQ BX
    PUSHQ BP
    PUSHQ R12
    PUSHQ R13
    PUSHQ R14
    PUSHQ R15

    /* CRITICAL: Set R15 to point to Ureg structure! */
    /* Offset of regs in PEB is 0x88 (136 decimal) */
    LEAQ 136(DI), R15

    /* Load Plan 9 registers from PEB.regs */
    /* RAX = regs.ax (offset 0) */
    MOVQ 0(R15), AX
    /* RBX = regs.bx (offset 8) */
    MOVQ 8(R15), BX
    /* RCX = regs.cx (offset 16) */
    MOVQ 16(R15), CX
    /* RDX = regs.dx (offset 24) */
    MOVQ 24(R15), DX
    /* RSI = regs.si (offset 32) */
    MOVQ 32(R15), SI
    /* RDI = regs.di (offset 40) */
    MOVQ 40(R15), DI
    /* RBP = regs.bp (offset 48) */
    MOVQ 48(R15), BP
    /* R8 = regs.r8 (offset 64) */
    MOVQ 64(R15), R8
    /* R9 = regs.r9 (offset 72) */
    MOVQ 72(R15), R9
    /* R10 = regs.r10 (offset 80) */
    MOVQ 80(R15), R10
    /* R11 = regs.r11 (offset 88) */
    MOVQ 88(R15), R11
    /* R12 = regs.r12 (offset 96) */
    MOVQ 96(R15), R12
    /* R13 = regs.r13 (offset 104) */
    MOVQ 104(R15), R13
    /* R14 = regs.r14 (offset 112) */
    MOVQ 112(R15), R14
    /* R15 is already set to point to Ureg */

    /* Load flags */
    MOVQ 120(R15), R11     /* regs.flags */
    PUSHQ R11
    POPFQ

    /* Load stack pointer */
    MOVQ 136(R15), SP     /* regs.sp */

    /* Load instruction pointer and jump */
    MOVQ 128(R15), R11     /* regs.ip */
    JMP R11

    /* If Plan 9 code returns (via syscall or exit), restore host state */
.plan9_return:
    /* Save return value */
    /* RAX contains the return value */

    /* Restore callee-saved registers */
    POPQ R15
    POPQ R14
    POPQ R13
    POPQ R12
    POPQ BP
    POPQ BX

    /* Return to caller */
    RET

.enter_error:
    MOVQ $-1, AX
    RET

/*
 * Helper function: get peb regs address
 * Returns the address of the regs field in the PEB
 *
 * Input:  DI = pointer to PEB
 * Output: AX = pointer to PEB.regs
 */
GLOBL get_peb_regs_addr(SB), $0
TEXT get_peb_regs_addr(SB), $0
    TESTQ DI, DI
    JEQ .get_error
    LEAQ 136(DI), AX     /* Offset of regs in PEB */
    RET
.get_error:
    XORQ AX, AX
    RET
