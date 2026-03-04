/*
 * Symbol test - debug version
 */
#include "../include/runtime/peb.h"
#include <stdio.h>

int main(void) {
    PEB *peb;
    P9Symbol *sym;
    int result;

    printf("Test 1: Create PEB and add symbols...\n");
    peb = peb_create();
    if (peb == NULL) {
        printf("FAILED: peb_create returned NULL\n");
        return 1;
    }

    result = peb_add_symbol(peb, "_main", 0x1000, P9_SYM_TEXT);
    printf("  add symbol _main: result=%d\n", result);

    result = peb_add_symbol(peb, "_print", 0x2000, P9_SYM_TEXT);
    printf("  add symbol _print: result=%d\n", result);

    printf("  nsymbols = %d\n", peb->nsymbols);
    printf("PASSED\n");

    printf("Test 2: Find symbol...\n");
    sym = peb_find_symbol(peb, "_main");
    if (sym == NULL) {
        printf("FAILED: peb_find_symbol returned NULL\n");
        peb_destroy(peb);
        return 1;
    }
    printf("  found: %s at 0x%lx type=%c\n",
           sym->name, (unsigned long)sym->value, sym->type);
    printf("PASSED\n");

    printf("Test 3: Cleanup...\n");
    peb_destroy(peb);
    printf("PASSED\n");

    printf("\nAll symbol tests passed!\n");
    return 0;
}
