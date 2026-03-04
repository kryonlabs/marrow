/*
 * Simple loader test
 */
#include "../include/loader/p9exec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    PEB *peb;
    FILE *fp;
    uint8_t header[32];
    uint8_t code[] = { 0xC3 };  /* ret */
    const char *symbol_name = "_main\0";
    uint64_t symbol_value = 0x1000;
    uint8_t symbol_type = 'T';

    printf("Creating test executable...\n");

    /* Create test executable */
    fp = fopen("test_simple.6", "wb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    memset(header, 0, 32);
    *(uint32_t *)(header + 0) = 0x8E;     /* Magic */
    *(uint32_t *)(header + 4) = 1;        /* Text size */
    *(uint32_t *)(header + 8) = 0;        /* Data size */
    *(uint32_t *)(header + 12) = 0;       /* BSS size */
    *(uint32_t *)(header + 16) = 8+1+6;   /* Symbol size: value + type + "_main\0" */
    *(uint32_t *)(header + 20) = 0x1000;  /* Entry */
    *(uint32_t *)(header + 24) = 8192;    /* Stack */

    fwrite(header, 32, 1, fp);
    fwrite(code, 1, 1, fp);
    fwrite(&symbol_value, 8, 1, fp);
    fwrite(&symbol_type, 1, 1, fp);
    fwrite(symbol_name, 7, 1, fp);

    fclose(fp);
    printf("Created test_simple.6\n");

    /* Try to load it */
    printf("Loading executable...\n");
    peb = p9_load_executable("test_simple.6", "test_simple");
    if (peb == NULL) {
        printf("Failed to load\n");
        return 1;
    }

    printf("Loaded successfully!\n");
    printf("  text.base = %p\n", (void *)peb->text.base);
    printf("  text.size = %u\n", peb->text.size);
    printf("  entry = 0x%lx\n", (unsigned long)peb->entry);
    printf("  nsymbols = %d\n", peb->nsymbols);

    peb_destroy(peb);
    return 0;
}
