/*
 * PEB Unit Tests
 * C89/C90 compliant
 *
 * Tests the Process Environment Block functionality
 */

#include "../include/runtime/peb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("Testing: %s...", #name); \
        if (test_##name()) { \
            tests_passed++; \
            printf(" PASSED\n"); \
        } else { \
            printf(" FAILED\n"); \
        } \
    } while(0)

int test_create_peb(void) {
    PEB *peb = peb_create();
    if (peb == NULL) return 0;

    if (peb->symbols == NULL) { peb_destroy(peb); return 0; }
    if (peb->nsymbols != 0) { peb_destroy(peb); return 0; }
    if (peb->state != P9_STATE_READY) { peb_destroy(peb); return 0; }

    peb_destroy(peb);
    return 1;
}

int test_alloc_text_segment(void) {
    PEB *peb;
    int result;

    peb = peb_create();
    if (peb == NULL) return 0;

    result = peb_alloc_segment(peb, &peb->text, 4096,
                              P9_PERM_READ | P9_PERM_EXEC);
    if (result < 0) { peb_destroy(peb); return 0; }

    if (peb->text.base == NULL) { peb_destroy(peb); return 0; }
    if (peb->text.size < 4096) { peb_destroy(peb); return 0; }

    peb_destroy(peb);
    return 1;
}

int test_alloc_data_segment(void) {
    PEB *peb;
    int result;

    peb = peb_create();
    if (peb == NULL) return 0;

    result = peb_alloc_segment(peb, &peb->data, 8192,
                              P9_PERM_READ | P9_PERM_WRITE);
    if (result < 0) { peb_destroy(peb); return 0; }

    if (peb->data.base == NULL) { peb_destroy(peb); return 0; }

    /* Test write access */
    memset(peb->data.base, 0xAA, 100);

    peb_destroy(peb);
    return 1;
}

int test_setup_stack(void) {
    PEB *peb;
    int result;

    peb = peb_create();
    if (peb == NULL) return 0;

    result = peb_setup_stack(peb, 65536);
    if (result < 0) { peb_destroy(peb); return 0; }

    if (peb->stack.base == NULL) { peb_destroy(peb); return 0; }
    if (peb->regs.sp == 0) { peb_destroy(peb); return 0; }

    peb_destroy(peb);
    return 1;
}

int test_symbol_operations(void) {
    PEB *peb;
    P9Symbol *sym;

    peb = peb_create();
    if (peb == NULL) return 0;

    /* Add symbols */
    if (peb_add_symbol(peb, "_main", 0x1000, P9_SYM_TEXT) < 0) {
        peb_destroy(peb);
        return 0;
    }

    if (peb_add_symbol(peb, "_print", 0x2000, P9_SYM_TEXT) < 0) {
        peb_destroy(peb);
        return 0;
    }

    if (peb->nsymbols != 2) {
        peb_destroy(peb);
        return 0;
    }

    /* Find symbol */
    sym = peb_find_symbol(peb, "_main");
    if (sym == NULL) {
        peb_destroy(peb);
        return 0;
    }

    if (sym->value != 0x1000) {
        peb_destroy(peb);
        return 0;
    }

    peb_destroy(peb);
    return 1;
}

int test_fd_management(void) {
    PEB *peb;
    P9FdEntry *entry;
    int fd1, fd2;

    peb = peb_create();
    if (peb == NULL) return 0;

    /* Allocate FDs */
    fd1 = peb_alloc_fd(peb);
    fd2 = peb_alloc_fd(peb);

    if (fd1 < 0 || fd2 < 0) {
        peb_destroy(peb);
        return 0;
    }

    if (fd1 == fd2) {
        peb_destroy(peb);
        return 0;
    }

    /* Get FD entry */
    entry = peb_get_fd(peb, fd1);
    if (entry == NULL) {
        peb_destroy(peb);
        return 0;
    }

    if (!entry->is_active) {
        peb_destroy(peb);
        return 0;
    }

    /* Close FD */
    if (peb_close_fd(peb, fd1) < 0) {
        peb_destroy(peb);
        return 0;
    }

    entry = peb_get_fd(peb, fd1);
    if (entry != NULL) {
        peb_destroy(peb);
        return 0;
    }

    peb_destroy(peb);
    return 1;
}

int test_register_accessors(void) {
    PEB *peb;
    uint64_t ax, sp;
    char buf[1024];
    int len;

    peb = peb_create();
    if (peb == NULL) return 0;

    /* Set registers (using smaller values to avoid C89 long long warnings) */
    peb->regs.ax = 0x12345678;
    peb->regs.sp = 0xFFFF0000;

    /* Test get */
    ax = peb_get_reg(peb, "AX");
    if (ax != 0x12345678) {
        peb_destroy(peb);
        return 0;
    }

    sp = peb_get_reg(peb, "SP");
    if (sp != 0xFFFF0000) {
        peb_destroy(peb);
        return 0;
    }

    /* Test set */
    if (peb_set_reg(peb, "R15", 0xDEADBEEF) < 0) {
        peb_destroy(peb);
        return 0;
    }

    if (peb->regs.r15 != 0xDEADBEEF) {
        peb_destroy(peb);
        return 0;
    }

    /* Test format registers */
    len = peb_format_regs(peb, buf, sizeof(buf));
    if (len <= 0) {
        peb_destroy(peb);
        return 0;
    }

    /* Check that key registers are in the output */
    if (strstr(buf, "AX") == NULL) {
        peb_destroy(peb);
        return 0;
    }

    peb_destroy(peb);
    return 1;
}

int test_full_peb_lifecycle(void) {
    PEB *peb;

    /* Create a complete PEB as the loader would */
    peb = peb_create();
    if (peb == NULL) return 0;

    /* Set process info */
    peb->pid = 1234;
    strncpy(peb->cmd, "test_program", sizeof(peb->cmd) - 1);
    peb->entry = 0x200000;
    peb->regs.ip = 0x200000;

    /* Allocate segments */
    if (peb_alloc_segment(peb, &peb->text, 4096, P9_PERM_READ | P9_PERM_EXEC) < 0) {
        peb_destroy(peb);
        return 0;
    }

    if (peb_alloc_segment(peb, &peb->data, 4096, P9_PERM_READ | P9_PERM_WRITE) < 0) {
        peb_destroy(peb);
        return 0;
    }

    if (peb_setup_stack(peb, 65536) < 0) {
        peb_destroy(peb);
        return 0;
    }

    /* Add symbols */
    peb_add_symbol(peb, "_main", 0x200000, P9_SYM_TEXT);
    peb_add_symbol(peb, "_p9sys_write", 0xDEADBEEF, P9_SYM_TEXT);

    /* Allocate some FDs */
    peb_alloc_fd(peb);  /* stdin */
    peb_alloc_fd(peb);  /* stdout */
    peb_alloc_fd(peb);  /* stderr */

    /* Print info for visual inspection */
    printf("\n");
    peb_print_info(peb);

    peb_destroy(peb);
    return 1;
}

int main(void) {
    printf("=== PEB Unit Tests ===\n\n");

    TEST(create_peb);
    TEST(alloc_text_segment);
    TEST(alloc_data_segment);
    TEST(setup_stack);
    TEST(symbol_operations);
    TEST(fd_management);
    TEST(register_accessors);
    TEST(full_peb_lifecycle);

    printf("\n=== Test Results ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);

    return (tests_passed == tests_run) ? 0 : 1;
}
