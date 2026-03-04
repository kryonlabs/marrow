/*
 * Test individual loader functions
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../include/loader/p9exec.h"
#include "../include/runtime/peb.h"

int main(void) {
    PEB *peb;

    fprintf(stderr, "Test 1: peb_create\n");
    peb = peb_create();
    if (peb == NULL) {
        fprintf(stderr, "FAILED: peb_create returned NULL\n");
        return 1;
    }
    fprintf(stderr, "PASSED: peb_create returned %p\n", (void *)peb);
    peb_destroy(peb);

    fprintf(stderr, "Test 2: p9exe_validate_header\n");
    P9Header header;
    header.magic = 0x8E;
    header.text = 4096;
    header.data = 0;
    header.bss = 0;
    header.syms = 0;
    header.entry = 0x1000;
    header.spsz = 8192;
    header.pcsz = 0;

    if (!p9exe_validate_header(&header)) {
        fprintf(stderr, "FAILED: p9exe_validate_header\n");
        return 1;
    }
    fprintf(stderr, "PASSED: p9exe_validate_header\n");

    fprintf(stderr, "Test 3: p9exe_print_header_info\n");
    p9exe_print_header_info(&header);

    fprintf(stderr, "\nAll tests passed!\n");
    return 0;
}
