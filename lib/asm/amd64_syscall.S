/*
 * AMD64 Syscall Gateway Assembly Stub
 * for Plan 9 Assembly Support in Marrow
 *
 * This stub is called when a patched SYSCALL instruction is executed.
 * It saves all registers, calls the C gateway handler, and restores.
 *
 * Calling convention:
 * - RAX = syscall number (Plan 9 convention)
 * - RDI, RSI, RDX, R10, R8, R9 = syscall arguments (System V convention)
 * - R15 = pointer to PEB (set by amd64_enter_plan9)
 */

/*
 * p9sys_gateway_stub - Syscall gateway entry point
 *
 * This function is called from patched SYSCALL instructions.
 * It must save all registers, call the C handler, and restore.
 *
 * Input:
 *   RAX = syscall number
 *   RDI, RSI, RDX, R10, R8, R9 = syscall arguments
 *   R15 = pointer to PEB (with regs pointing to Ureg)
 *
 * Output:
 *   RAX = syscall return value
 */
.global p9sys_gateway_stub
.type p9sys_gateway_stub, @function
p9sys_gateway_stub:
    /* Save all registers to the stack */
    /* We need to save the Plan 9 calling convention registers */
    push %rax          /* Syscall number */
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15

    /* Save stack pointer for debugging */
    mov %rsp, %rbp

    /* Setup arguments for C function call */
    /* int64_t p9sys_gateway(PEB *peb, int syscall_num, uint64_t *args) */

    /* RDI = PEB pointer */
    /* R15 points to Ureg, we need to get PEB pointer */
    /* Ureg is at offset 136 in PEB */
    mov %r15, %rdi
    sub $136, %rdi     /* PEB = &Ureg - offset */

    /* RSI = syscall number */
    movq 0(%rsp), %rsi   /* Get saved RAX from stack */

    /* RDX = pointer to arguments array */
    /* Arguments are in RDI, RSI, RDX, R10, R8, R9 */
    /* But we've saved them on the stack */
    /* Point to saved registers on stack */
    leaq 48(%rsp), %rdx  /* Skip RAX, RBX, RCX, RDX, RSI, RDI */

    /* Align stack to 16 bytes */
    and $-16, %rsp

    /* Make stack space for arguments array */
    sub $64, %rsp

    /* Copy arguments from saved registers to array */
    /* Order: RDI, RSI, RDX, R10, R8, R9 */
    movq 48(%rbp), %rax   /* Saved RDI */
    movq %rax, 0(%rsp)
    movq 56(%rbp), %rax   /* Saved RSI */
    movq %rax, 8(%rsp)
    movq 64(%rbp), %rax   /* Saved RDX */
    movq %rax, 16(%rsp)
    movq 104(%rbp), %rax  /* Saved R10 */
    movq %rax, 24(%rsp)
    movq 112(%rbp), %rax  /* Saved R8 */
    movq %rax, 32(%rsp)
    movq 120(%rbp), %rax  /* Saved R9 */
    movq %rax, 40(%rsp)

    /* Pass array pointer as third argument */
    mov %rsp, %rdx

    /* Call C gateway handler */
    call p9sys_gateway

    /* Restore stack pointer */
    mov %rbp, %rsp

    /* Restore all registers */
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx

    /* Restore syscall return value to RAX */
    /* The C function returns in RAX, which is on top of stack */
    add $8, %rsp        /* Skip saved RAX */
    push %rax           /* Push return value */

    /* Restore RAX with return value */
    pop %rax

    /* Return to caller */
    ret
.size p9sys_gateway_stub, .-p9sys_gateway_stub

/*
 * Alternative simpler version
 * Just save registers and call C handler directly
 */
.global p9sys_gateway_stub_simple
.type p9sys_gateway_stub_simple, @function
p9sys_gateway_stub_simple:
    /* Save all registers */
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15

    /* Save RSP */
    mov %rsp, %r11

    /* R15 points to Ureg, get PEB pointer */
    mov %r15, %rdi
    sub $136, %rdi

    /* Syscall number is on stack (first push) */
    mov 120(%r11), %rsi

    /* Create args array on stack */
    sub $64, %rsp
    and $-16, %rsp

    /* Copy argument registers to array */
    /* Original args before syscall were in RDI, RSI, RDX, RCX, R8, R9 */
    /* But Plan 9 uses RDI, RSI, RDX, R10, R8, R9 */
    /* System V uses RDI, RSI, RDX, RCX, R8, R9 */
    /* So we need to handle this properly */

    /* For now, just use the register values */
    movq 104(%r11), %rax  /* Saved RDI */
    movq %rax, (%rsp)
    movq 96(%r11), %rax   /* Saved RSI */
    movq %rax, 8(%rsp)
    movq 88(%r11), %rax   /* Saved RDX */
    movq %rax, 16(%rsp)
    movq 56(%r11), %rax   /* Saved R10 */
    movq %rax, 24(%rsp)
    movq 48(%r11), %rax   /* Saved R8 */
    movq %rax, 32(%rsp)
    movq 40(%r11), %rax   /* Saved R9 */
    movq %rax, 40(%rsp)

    mov %rsp, %rdx        /* Third arg: args array */

    /* Call C handler */
    call p9sys_gateway

    /* Restore stack */
    mov %r11, %rsp
    add $64, %rsp

    /* Restore registers (except RAX which has return value) */
    add $8, %rsp          /* Skip saved RAX */
    pop %rbx
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi
    pop %rbp
    pop %r8
    pop %r9
    pop %r10
    pop %r11
    pop %r12
    pop %r13
    pop %r14
    pop %r15

    /* RAX already has return value from C function */
    ret
.size p9sys_gateway_stub_simple, .-p9sys_gateway_stub_simple
