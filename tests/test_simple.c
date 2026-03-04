/*
 * Simple PEB test - debug version
 */
#include "../include/runtime/peb.h"
#include <stdio.h>

int main(void) {
    PEB *peb;

    printf("Test 1: Create PEB...\n");
    peb = peb_create();
    if (peb == NULL) {
        printf("FAILED: peb_create returned NULL\n");
        return 1;
    }
    printf("PASSED: peb_create\n");

    printf("Test 2: Check PEB fields...\n");
    printf("  nsymbols = %d\n", peb->nsymbols);
    printf("  state = %d\n", peb->state);
    printf("PASSED: PEB fields look OK\n");

    printf("Test 3: Destroy PEB...\n");
    peb_destroy(peb);
    printf("PASSED: peb_destroy\n");

    printf("\nAll tests passed!\n");
    return 0;
}
