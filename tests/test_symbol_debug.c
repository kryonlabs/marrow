/*
 * Symbol test - debug version with more output
 */
#include "../include/runtime/peb.h"
#include <stdio.h>

int main(void) {
    PEB *peb;
    P9Symbol *sym;
    int result;

    printf("Test 1: Create PEB...\n");
    peb = peb_create();
    if (peb == NULL) {
        printf("FAILED: peb_create returned NULL\n");
        return 1;
    }
    printf("  peb created\n");
    printf("  symbols=%p nsymbols=%d capacity=%d\n",
           (void *)peb->symbols, peb->nsymbols, peb->symbol_capacity);
    printf("PASSED\n");

    printf("Test 2: Add first symbol...\n");
    printf("  calling peb_add_symbol...\n");
    result = peb_add_symbol(peb, "_main", 0x1000, P9_SYM_TEXT);
    printf("  result=%d\n", result);
    printf("  nsymbols=%d\n", peb->nsymbols);
    printf("PASSED\n");

    printf("Test 3: Find symbol...\n");
    printf("  calling peb_find_symbol...\n");
    sym = peb_find_symbol(peb, "_main");
    printf("  sym=%p\n", (void *)sym);
    if (sym == NULL) {
        printf("FAILED: peb_find_symbol returned NULL\n");
        peb_destroy(peb);
        return 1;
    }
    printf("  found: %s at 0x%lx\n",
           sym->name, (unsigned long)sym->value);
    printf("PASSED\n");

    printf("Test 4: Cleanup...\n");
    peb_destroy(peb);
    printf("PASSED\n");

    printf("\nAll tests passed!\n");
    return 0;
}
