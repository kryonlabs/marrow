/*
 * Debug loader test with stderr output
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../include/loader/p9exec.h"

int main(void) {
    FILE *fp;
    uint8_t header[32];
    uint8_t code[] = { 0xC3 };  /* ret */

    fprintf(stderr, "DEBUG: Step 1 - Creating test executable\n");

    /* Create test executable */
    fp = fopen("test_debug.6", "wb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    fprintf(stderr, "DEBUG: Step 2 - Writing header\n");

    memset(header, 0, 32);
    *(uint32_t *)(header + 0) = 0x8E;     /* Magic */
    *(uint32_t *)(header + 4) = 1;        /* Text size */
    *(uint32_t *)(header + 20) = 0x1000;  /* Entry */

    fwrite(header, 32, 1, fp);
    fwrite(code, 1, 1, fp);

    fclose(fp);

    fprintf(stderr, "DEBUG: Step 3 - File created\n");

    /* Try to load using loader */
    fprintf(stderr, "DEBUG: Step 4 - About to call loader\n");

    PEB *peb = p9_load_executable("test_debug.6", "test_debug");

    fprintf(stderr, "DEBUG: Step 5 - Loader returned peb=%p\n", (void *)peb);

    if (peb == NULL) {
        fprintf(stderr, "DEBUG: Failed to load\n");
        return 1;
    }

    fprintf(stderr, "DEBUG: Success!\n");

    return 0;
}
