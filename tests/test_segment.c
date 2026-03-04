/*
 * Segment allocation test - debug version
 */
#include "../include/runtime/peb.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    PEB *peb;
    int result;

    printf("Test 1: Create PEB...\n");
    peb = peb_create();
    if (peb == NULL) {
        printf("FAILED: peb_create returned NULL\n");
        return 1;
    }
    printf("PASSED\n");

    printf("Test 2: Allocate text segment...\n");
    result = peb_alloc_segment(peb, &peb->text, 4096,
                              P9_PERM_READ | P9_PERM_EXEC);
    if (result < 0) {
        printf("FAILED: peb_alloc_segment returned %d\n", result);
        peb_destroy(peb);
        return 1;
    }
    printf("  text.base = %p\n", (void *)peb->text.base);
    printf("  text.size = %u\n", peb->text.size);
    printf("PASSED\n");

    printf("Test 3: Allocate data segment...\n");
    result = peb_alloc_segment(peb, &peb->data, 8192,
                              P9_PERM_READ | P9_PERM_WRITE);
    if (result < 0) {
        printf("FAILED: peb_alloc_segment returned %d\n", result);
        peb_destroy(peb);
        return 1;
    }
    printf("  data.base = %p\n", (void *)peb->data.base);
    printf("  data.size = %u\n", peb->data.size);

    /* Test write */
    printf("Test 4: Write to data segment...\n");
    memset(peb->data.base, 0xAA, 100);
    printf("PASSED\n");

    printf("Test 5: Setup stack...\n");
    result = peb_setup_stack(peb, 65536);
    if (result < 0) {
        printf("FAILED: peb_setup_stack returned %d\n", result);
        peb_destroy(peb);
        return 1;
    }
    printf("  stack.base = %p\n", (void *)peb->stack.base);
    printf("  stack.size = %u\n", peb->stack.size);
    printf("  regs.sp = %lx\n", (unsigned long)peb->regs.sp);
    printf("PASSED\n");

    printf("Test 6: Cleanup...\n");
    peb_destroy(peb);
    printf("PASSED\n");

    printf("\nAll segment tests passed!\n");
    return 0;
}
