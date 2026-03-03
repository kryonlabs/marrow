/*
 * AMD64 Context Switching Assembly Stubs
 * for Plan 9 Assembly Support in Marrow
 *
 * This file contains the low-level assembly routines for
 * switching between System V AMD64 (Linux) and Plan 9 calling conventions.
 *
 * CRITICAL: In Plan 9 amd64, R15 MUST point to the Ureg structure!
 * This is how Plan 9 code finds its register save area during syscalls.
 */

/*
 * amd64_save_context - Save all host registers
 *
 * Input:  RDI = pointer to ContextFrame
 * Output: RAX = 0 on success, -1 on error
 * Clobbers: RAX, RCX, RDX
 */
.global amd64_save_context
.type amd64_save_context, @function
amd64_save_context:
    /* Check for NULL pointer */
    test %rdi, %rdi
    je .save_error

    /* Save RAX first (since we're using it) */
    movq %rax, (%rdi)

    /* Save all registers to context frame */
    movq %rbx, 8(%rdi)
    movq %rcx, 16(%rdi)
    movq %rdx, 24(%rdi)
    movq %rsi, 32(%rdi)
    movq %rdi, 40(%rdi)      /* Save original RDI */
    movq %rbp, 48(%rdi)
    movq %rsp, 56(%rdi)
    movq %r8,  64(%rdi)
    movq %r9,  72(%rdi)
    movq %r10, 80(%rdi)
    movq %r11, 88(%rdi)
    movq %r12, 96(%rdi)
    movq %r13, 104(%rdi)
    movq %r14, 112(%rdi)
    movq %r15, 120(%rdi)

    /* Save RFLAGS */
    pushfq
    popq %rax
    movq %rax, 128(%rdi)

    /* Save RSP and RBP separately */
    movq %rsp, 136(%rdi)
    movq %rbp, 144(%rdi)

    /* Return success */
    xorq %rax, %rax
    ret

.save_error:
    movq $-1, %rax
    ret
.size amd64_save_context, .-amd64_save_context

/*
 * amd64_restore_context - Restore all host registers
 *
 * Input:  RDI = pointer to ContextFrame
 * Output: RAX = 0 on success, -1 on error
 * Clobbers: RCX, RDX
 */
.global amd64_restore_context
.type amd64_restore_context, @function
amd64_restore_context:
    /* Check for NULL pointer */
    test %rdi, %rdi
    je .restore_error

    /* Restore all registers from context frame */
    movq (%rdi), %rax
    movq 8(%rdi), %rbx
    movq 16(%rdi), %rcx
    movq 24(%rdi), %rdx
    movq 32(%rdi), %rsi
    movq 40(%rdi), %rbp      /* We'll restore RDI last */
    movq 48(%rdi), %rbp
    movq 56(%rdi), %rsp
    movq 64(%rdi), %r8
    movq 72(%rdi), %r9
    movq 80(%rdi), %r10
    movq 88(%rdi), %r11
    movq 96(%rdi), %r12
    movq 104(%rdi), %r13
    movq 112(%rdi), %r14
    movq 120(%rdi), %r15

    /* Restore RFLAGS */
    movq 128(%rdi), %rax
    pushq %rax
    popfq

    /* Restore RSP and RBP */
    movq 136(%rdi), %rsp
    movq 144(%rdi), %rbp

    /* Restore RDI last (it's our pointer to the context frame) */
    movq 40(%rdi), %rdi

    /* Return success */
    xorq %rax, %rax
    ret

.restore_error:
    movq $-1, %rax
    ret
.size amd64_restore_context, .-amd64_restore_context

/*
 * amd64_enter_plan9 - Enter Plan 9 execution mode
 *
 * CRITICAL: This function MUST set R15 to point to the Ureg structure!
 * Plan 9 code expects R15 to always point to its register save area.
 *
 * Input:  RDI = pointer to PEB
 * Output: Does not return (jumps to Plan 9 entry point)
 *
 * PEB structure layout:
 *   +0x00:  pid (int)
 *   +0x04:  cmd[64] (char array)
 *   +0x44:  active (int)
 *   +0x48:  text segment
 *   +0x54:  data segment
 *   +0x60:  bss segment
 *   +0x6C:  stack segment
 *   +0x78:  symbols pointer
 *   +0x80:  nsymbols (int)
 *   +0x84:  symbol_capacity (int)
 *   +0x88:  regs (Ureg structure) <- WE NEED TO POINT R15 HERE!
 *   +0x88:  regs.ax
 *   +0x90:  regs.bx
 *   +0x98:  regs.cx
 *   +0xA0:  regs.dx
 *   +0xA8:  regs.si
 *   +0xB0:  regs.di
 *   +0xB8:  regs.bp
 *   +0xC0:  regs.r8
 *   +0xC8:  regs.r9
 *   +0xD0:  regs.r10
 *   +0xD8:  regs.r11
 *   +0xE0:  regs.r12
 *   +0xE8:  regs.r13
 *   +0xF0:  regs.r14
 *   +0xF8:  regs.r15
 *   +0x100: regs.ip
 *   +0x108: regs.flags
 *   +0x110: regs.sp
 */
.global amd64_enter_plan9
.type amd64_enter_plan9, @function
amd64_enter_plan9:
    /* Check for NULL pointer */
    test %rdi, %rdi
    jz .enter_error

    /* Save callee-saved registers (we'll need these after Plan 9 returns) */
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15

    /* CRITICAL: Set R15 to point to Ureg structure! */
    /* Offset of regs in PEB is 0x88 (136 decimal) */
    leaq 136(%rdi), %r15

    /* Load Plan 9 registers from PEB.regs */
    /* RAX = regs.ax (offset 0) */
    movq 0(%r15), %rax
    /* RBX = regs.bx (offset 8) */
    movq 8(%r15), %rbx
    /* RCX = regs.cx (offset 16) */
    movq 16(%r15), %rcx
    /* RDX = regs.dx (offset 24) */
    movq 24(%r15), %rdx
    /* RSI = regs.si (offset 32) */
    movq 32(%r15), %rsi
    /* RDI = regs.di (offset 40) */
    movq 40(%r15), %rdi
    /* RBP = regs.bp (offset 48) */
    movq 48(%r15), %rbp
    /* R8 = regs.r8 (offset 64) */
    movq 64(%r15), %r8
    /* R9 = regs.r9 (offset 72) */
    movq 72(%r15), %r9
    /* R10 = regs.r10 (offset 80) */
    movq 80(%r15), %r10
    /* R11 = regs.r11 (offset 88) */
    movq 88(%r15), %r11
    /* R12 = regs.r12 (offset 96) */
    movq 96(%r15), %r12
    /* R13 = regs.r13 (offset 104) */
    movq 104(%r15), %r13
    /* R14 = regs.r14 (offset 112) */
    movq 112(%r15), %r14
    /* R15 is already set to point to Ureg */

    /* Load flags */
    movq 120(%r15), %r11     /* regs.flags */
    pushq %r11
    popfq

    /* Load stack pointer */
    movq 136(%r15), %rsp     /* regs.sp */

    /* Load instruction pointer and jump */
    movq 128(%r15), %r11     /* regs.ip */
    jmp *%r11

    /* If Plan 9 code returns (via syscall or exit), restore host state */
.plan9_return:
    /* Save return value */
    /* RAX contains the return value */

    /* Restore callee-saved registers */
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx

    /* Return to caller */
    ret

.enter_error:
    movq $-1, %rax
    ret
.size amd64_enter_plan9, .-amd64_enter_plan9

/*
 * Helper function: get peb regs address
 * Returns the address of the regs field in the PEB
 *
 * Input:  RDI = pointer to PEB
 * Output: RAX = pointer to PEB.regs
 */
.global get_peb_regs_addr
.type get_peb_regs_addr, @function
get_peb_regs_addr:
    test %rdi, %rdi
    jz .get_error
    leaq 136(%rdi), %rax     /* Offset of regs in PEB */
    ret
.get_error:
    xorq %rax, %rax
    ret
.size get_peb_regs_addr, .-get_peb_regs_addr
