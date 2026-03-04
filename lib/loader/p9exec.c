/*
 * Plan 9 Executable Loader Implementation
 * C89/C90 compliant
 *
 * Loads Plan 9 executables (6l/8l/5l output format) into memory
 * and prepares them for execution within Marrow.
 */

#include "loader/p9exec.h"
#include "lib9p.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

/*
 * Virtual symbol table - C functions callable from Plan 9 assembly
 * These symbols are resolved by the loader and can be called from
 * Plan 9 assembly code via standard CALL instructions.
 */
static const struct {
    const char *name;
    void *addr;
} g_virtual_symbols[] = {
    /* File operations */
    {"_p9sys_open",    NULL},  /* Set at runtime */
    {"_p9sys_read",    NULL},
    {"_p9sys_write",   NULL},
    {"_p9sys_close",   NULL},
    {"_p9sys_create",  NULL},
    {"_p9sys_remove",  NULL},
    {"_p9sys_seek",    NULL},

    /* Directory operations */
    {"_p9sys_bind",    NULL},
    {"_p9sys_mount",   NULL},
    {"_p9sys_unmount", NULL},

    /* Process operations */
    {"_p9sys_exec",    NULL},
    {"_p9sys_exits",   NULL},
    {"_p9sys_brk_",    NULL},
    {"_p9sys_sleep",   NULL},

    /* Termination */
    {"_p9sys__exits",  NULL},  /* underscore version */

    {NULL, NULL}
};

/*
 * Initialize the loader module
 */
int p9_loader_init(void)
{
    /* Virtual symbol addresses will be set by syscall module */
    (void)g_virtual_symbols;  /* Suppress unused warning */
    return 0;
}

/*
 * Cleanup the loader module
 */
void p9_loader_cleanup(void)
{
    /* Nothing to cleanup currently */
}

/*
 * Validate a Plan 9 executable header
 */
int p9exe_validate_header(const P9Header *header)
{
    if (header == NULL) {
        fprintf(stderr, "p9exe_validate_header: NULL header\n");
        return 0;
    }

    /* Check magic number */
    if (header->magic != P9_MAGIC_AMD64 &&
        header->magic != P9_MAGIC_I386 &&
        header->magic != P9_MAGIC_ARM64) {
        fprintf(stderr, "p9exe_validate_header: invalid magic 0x%x\n",
                header->magic);
        return 0;
    }

    /* Validate sizes are reasonable */
    if (header->text > 1024 * 1024 * 256) {  /* 256 MB max text */
        fprintf(stderr, "p9exe_validate_header: text too large: %u\n",
                header->text);
        return 0;
    }

    if (header->data > 1024 * 1024 * 256) {  /* 256 MB max data */
        fprintf(stderr, "p9exe_validate_header: data too large: %u\n",
                header->data);
        return 0;
    }

    if (header->bss > 1024 * 1024 * 256) {  /* 256 MB max bss */
        fprintf(stderr, "p9exe_validate_header: bss too large: %u\n",
                header->bss);
        return 0;
    }

    return 1;
}

/*
 * Parse the Plan 9 executable header
 */
int p9exe_parse_header(FILE *fp, P9Header *header)
{
    uint32_t raw_header[8];  /* 8 * 4 = 32 bytes */
    size_t nread;

    if (fp == NULL || header == NULL) {
        fprintf(stderr, "p9exe_parse_header: NULL argument\n");
        return -1;
    }

    /* Read 32-byte header */
    nread = fread(raw_header, 4, 8, fp);
    if (nread != 8) {
        fprintf(stderr, "p9exe_parse_header: read failed\n");
        return -1;
    }

    /* Extract fields (Plan 9 uses little-endian) */
    header->magic  = raw_header[0];
    header->text   = raw_header[1];
    header->data   = raw_header[2];
    header->bss    = raw_header[3];
    header->syms   = raw_header[4];
    header->entry  = raw_header[5];
    header->spsz   = raw_header[6];
    header->pcsz   = raw_header[7];

    /* Validate header */
    if (!p9exe_validate_header(header)) {
        return -1;
    }

    return 0;
}

/*
 * Load segments from executable
 */
int p9exe_load_segments(FILE *fp, PEB *peb, const P9Header *header)
{
    size_t nread;
    uint32_t text_size;
    uint32_t data_size;
    uint32_t bss_size;

    fprintf(stderr, "p9exe_load_segments: Starting\n");
    fflush(stderr);

    if (fp == NULL || peb == NULL || header == NULL) {
        fprintf(stderr, "p9exe_load_segments: NULL argument\n");
        return -1;
    }

    text_size = header->text;
    data_size = header->data;
    bss_size = header->bss;

    fprintf(stderr, "p9exe_load_segments: text=%u data=%u bss=%u\n",
            text_size, data_size, bss_size);
    fflush(stderr);

    /* Allocate and load text segment (RX) */
    if (text_size > 0) {
        fprintf(stderr, "p9exe_load_segments: Allocating text segment\n");
        fflush(stderr);

        /* Allocate with RW permissions first, then make RX after loading */
        if (peb_alloc_segment(peb, &peb->text, text_size,
                             P9_PERM_READ | P9_PERM_WRITE) < 0) {
            fprintf(stderr, "p9exe_load_segments: text alloc failed\n");
            return -1;
        }

        fprintf(stderr, "p9exe_load_segments: Reading text segment\n");
        fflush(stderr);
        nread = fread(peb->text.base, 1, text_size, fp);
        if (nread != text_size) {
            fprintf(stderr, "p9exe_load_segments: text read failed\n");
            return -1;
        }

        /* Now make it RX (no write) */
        if (mprotect(peb->text.base, peb->text.size,
                    PROT_READ | PROT_EXEC) < 0) {
            perror("p9exe_load_segments: mprotect text to RX failed");
            return -1;
        }

        fprintf(stderr, "p9exe_load_segments: Text segment loaded and protected\n");
        fflush(stderr);
    }

    /* Allocate and load data segment (RW) */
    if (data_size > 0) {
        if (peb_alloc_segment(peb, &peb->data, data_size,
                             P9_PERM_READ | P9_PERM_WRITE) < 0) {
            fprintf(stderr, "p9exe_load_segments: data alloc failed\n");
            return -1;
        }

        nread = fread(peb->data.base, 1, data_size, fp);
        if (nread != data_size) {
            fprintf(stderr, "p9exe_load_segments: data read failed\n");
            return -1;
        }
    }

    /* Allocate BSS segment (RW, zero-initialized) */
    if (bss_size > 0) {
        if (peb_alloc_segment(peb, &peb->bss, bss_size,
                             P9_PERM_READ | P9_PERM_WRITE) < 0) {
            fprintf(stderr, "p9exe_load_segments: bss alloc failed\n");
            return -1;
        }

        /* BSS is already zero-initialized by peb_alloc_segment */
    }

    return 0;
}

/*
 * Load symbol table from executable
 */
int p9exe_load_symbols(FILE *fp, PEB *peb, const P9Header *header)
{
    uint8_t *sym_buffer;
    uint32_t syms_size;
    uint32_t offset;
    size_t nread;
    int result;

    if (fp == NULL || peb == NULL || header == NULL) {
        fprintf(stderr, "p9exe_load_symbols: NULL argument\n");
        return -1;
    }

    syms_size = header->syms;

    if (syms_size == 0) {
        /* No symbols */
        return 0;
    }

    /* Allocate buffer for symbol table */
    sym_buffer = (uint8_t *)malloc(syms_size);
    if (sym_buffer == NULL) {
        fprintf(stderr, "p9exe_load_symbols: malloc failed\n");
        return -1;
    }

    /* Read symbol table */
    nread = fread(sym_buffer, 1, syms_size, fp);
    if (nread != syms_size) {
        fprintf(stderr, "p9exe_load_symbols: read failed\n");
        free(sym_buffer);
        return -1;
    }

    /* Parse symbol entries */
    offset = 0;
    result = 0;

    while (offset < syms_size) {
        uint64_t value;
        uint8_t type;
        char *name;
        int name_len;

        /* Extract value (little-endian 64-bit) */
        if (offset + 8 > syms_size) {
            fprintf(stderr, "p9exe_load_symbols: truncated value\n");
            result = -1;
            break;
        }

        value = *(uint64_t *)(sym_buffer + offset);
        offset += 8;

        /* Extract type */
        if (offset >= syms_size) {
            fprintf(stderr, "p9exe_load_symbols: truncated type\n");
            result = -1;
            break;
        }

        type = sym_buffer[offset];
        offset += 1;

        /* Extract name (null-terminated) — bounded scan to avoid overread */
        name = (char *)(sym_buffer + offset);
        name_len = 0;
        while (offset + name_len < syms_size && sym_buffer[offset + name_len] != '\0')
            name_len++;
        if (offset + name_len >= syms_size) {
            fprintf(stderr, "p9exe_load_symbols: name not null-terminated\n");
            result = -1;
            break;
        }
        offset += name_len + 1;  /* +1 for null terminator */

        /* Add to symbol table */
        if (peb_add_symbol(peb, name, value, type) < 0) {
            fprintf(stderr, "p9exe_load_symbols: add symbol failed\n");
            result = -1;
            break;
        }
    }

    free(sym_buffer);

    if (result == 0) {
        /* Sort symbols for faster lookup */
        peb_sort_symbols(peb);
    }

    return result;
}

/*
 * Setup virtual symbols (C functions callable from Plan 9 assembly)
 */
int p9exe_setup_virtual_symbols(PEB *peb)
{
    int i;

    if (peb == NULL) {
        fprintf(stderr, "p9exe_setup_virtual_symbols: NULL peb\n");
        return -1;
    }

    /* Add virtual symbols to symbol table */
    for (i = 0; g_virtual_symbols[i].name != NULL; i++) {
        /* These will be resolved by the syscall module */
        /* For now, add with address 0 */
        if (peb_add_symbol(peb, g_virtual_symbols[i].name,
                          0, P9_SYM_TEXT) < 0) {
            fprintf(stderr, "p9exe_setup_virtual_symbols: failed to add %s\n",
                    g_virtual_symbols[i].name);
            return -1;
        }
    }

    return 0;
}

/*
 * Print executable information for debugging
 */
void p9exe_print_header_info(const P9Header *header)
{
    const char *arch_str;

    if (header == NULL) {
        printf("Header: NULL\n");
        return;
    }

    /* Determine architecture */
    switch (header->magic) {
        case P9_MAGIC_AMD64:
            arch_str = "amd64 (6l)";
            break;
        case P9_MAGIC_I386:
            arch_str = "i386 (8l)";
            break;
        case P9_MAGIC_ARM64:
            arch_str = "arm64 (5l)";
            break;
        default:
            arch_str = "unknown";
            break;
    }

    printf("=== Plan 9 Executable Header ===\n");
    printf("Architecture: %s\n", arch_str);
    printf("Text:        %u bytes\n", header->text);
    printf("Data:        %u bytes\n", header->data);
    printf("BSS:         %u bytes\n", header->bss);
    printf("Symbols:     %u bytes\n", header->syms);
    printf("Entry:       0x%x\n", header->entry);
    printf("Stack:       %u bytes\n", header->spsz);
    printf("PC size:     %u bytes\n", header->pcsz);
    printf("\n");
}

/*
 * Load a Plan 9 executable from a file
 */
PEB *p9_load_executable(const char *path, const char *cmd)
{
    FILE *fp;
    P9Header header;
    PEB *peb;
    uint32_t stack_size;
    int result;

    if (path == NULL || cmd == NULL) {
        fprintf(stderr, "p9_load_executable: NULL argument\n");
        return NULL;
    }

    /* Open file */
    fprintf(stderr, "p9_load_executable: Opening file %s\n", path);
    fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("p9_load_executable: fopen failed");
        return NULL;
    }
    fprintf(stderr, "p9_load_executable: File opened\n");

    /* Parse header */
    fprintf(stderr, "p9_load_executable: Parsing header\n");
    if (p9exe_parse_header(fp, &header) < 0) {
        fclose(fp);
        return NULL;
    }
    fprintf(stderr, "p9_load_executable: Header parsed\n");

    /* Print header info for debugging */
    p9exe_print_header_info(&header);

    /* Create PEB */
    fprintf(stderr, "p9_load_executable: Creating PEB\n");
    peb = peb_create();
    if (peb == NULL) {
        fclose(fp);
        return NULL;
    }
    fprintf(stderr, "p9_load_executable: PEB created\n");
    fflush(stderr);

    /* Check for NULL */
    if (peb == NULL || cmd == NULL) {
        fprintf(stderr, "p9_load_executable: NULL detected\n");
        fflush(stderr);
        fclose(fp);
        return NULL;
    }

    /* Set command name */
    fprintf(stderr, "p9_load_executable: About to strncpy\n");
    fflush(stderr);
    strncpy(peb->cmd, cmd, sizeof(peb->cmd) - 1);
    peb->cmd[sizeof(peb->cmd) - 1] = '\0';
    fprintf(stderr, "p9_load_executable: Command name set to %s\n", peb->cmd);
    fflush(stderr);

    /* Set entry point */
    fprintf(stderr, "p9_load_executable: Setting entry point\n");
    peb->entry = header.entry;
    peb->regs.ip = header.entry;
    fprintf(stderr, "p9_load_executable: Entry point set\n");

    /* Load segments */
    fprintf(stderr, "p9_load_executable: Loading segments\n");
    if (p9exe_load_segments(fp, peb, &header) < 0) {
        fprintf(stderr, "p9_load_executable: segment load failed\n");
        peb_destroy(peb);
        fclose(fp);
        return NULL;
    }
    fprintf(stderr, "p9_load_executable: Segments loaded\n");

    /* Load symbols */
    if (p9exe_load_symbols(fp, peb, &header) < 0) {
        fprintf(stderr, "p9_load_executable: symbol load failed\n");
        peb_destroy(peb);
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    /* Setup stack */
    stack_size = header.spsz;
    if (stack_size == 0) {
        stack_size = 8 * 1024 * 1024;  /* Default 8 MB */
    }

    if (peb_setup_stack(peb, stack_size) < 0) {
        fprintf(stderr, "p9_load_executable: stack setup failed\n");
        peb_destroy(peb);
        return NULL;
    }

    /* Setup virtual symbols */
    result = p9exe_setup_virtual_symbols(peb);
    if (result < 0) {
        fprintf(stderr, "p9_load_executable: virtual symbols failed\n");
        /* Non-fatal, continue anyway */
    }

    /* Mark as active */
    peb->active = 1;

    fprintf(stderr, "p9_load_executable: loaded %s successfully\n", cmd);

    return peb;
}

/*
 * Load a Plan 9 executable from memory buffer
 */
PEB *p9_load_executable_from_memory(const uint8_t *buffer, size_t size,
                                    const char *cmd)
{
    P9Header header;
    PEB *peb;
    uint32_t offset;
    uint32_t stack_size;
    int result;

    if (buffer == NULL || cmd == NULL) {
        fprintf(stderr, "p9_load_executable_from_memory: NULL argument\n");
        return NULL;
    }

    if (size < 32) {
        fprintf(stderr, "p9_load_executable_from_memory: buffer too small\n");
        return NULL;
    }

    /* Parse header from buffer */
    offset = 0;
    header.magic  = *(uint32_t *)(buffer + offset); offset += 4;
    header.text   = *(uint32_t *)(buffer + offset); offset += 4;
    header.data   = *(uint32_t *)(buffer + offset); offset += 4;
    header.bss    = *(uint32_t *)(buffer + offset); offset += 4;
    header.syms   = *(uint32_t *)(buffer + offset); offset += 4;
    header.entry  = *(uint32_t *)(buffer + offset); offset += 4;
    header.spsz   = *(uint32_t *)(buffer + offset); offset += 4;
    header.pcsz   = *(uint32_t *)(buffer + offset); offset += 4;

    /* Validate header */
    if (!p9exe_validate_header(&header)) {
        return NULL;
    }

    /* Print header info for debugging */
    p9exe_print_header_info(&header);

    /* Check buffer size */
    if (size < 32 + header.text + header.data + header.syms) {
        fprintf(stderr, "p9_load_executable_from_memory: buffer truncated\n");
        return NULL;
    }

    /* Create PEB */
    peb = peb_create();
    if (peb == NULL) {
        return NULL;
    }

    /* Set command name */
    strncpy(peb->cmd, cmd, sizeof(peb->cmd) - 1);
    peb->cmd[sizeof(peb->cmd) - 1] = '\0';

    /* Set entry point */
    peb->entry = header.entry;
    peb->regs.ip = header.entry;

    /* Copy text segment */
    if (header.text > 0) {
        /* Allocate with RW first, then make RX after copying */
        if (peb_alloc_segment(peb, &peb->text, header.text,
                             P9_PERM_READ | P9_PERM_WRITE) < 0) {
            fprintf(stderr, "p9_load_executable_from_memory: text alloc failed\n");
            peb_destroy(peb);
            return NULL;
        }

        memcpy(peb->text.base, buffer + offset, header.text);
        offset += header.text;

        if (mprotect(peb->text.base, peb->text.size,
                    PROT_READ | PROT_EXEC) < 0) {
            perror("p9_load_executable_from_memory: mprotect text to RX failed");
            peb_destroy(peb);
            return NULL;
        }
    }

    /* Copy data segment */
    if (header.data > 0) {
        if (peb_alloc_segment(peb, &peb->data, header.data,
                             P9_PERM_READ | P9_PERM_WRITE) < 0) {
            fprintf(stderr, "p9_load_executable_from_memory: data alloc failed\n");
            peb_destroy(peb);
            return NULL;
        }

        memcpy(peb->data.base, buffer + offset, header.data);
        offset += header.data;
    }

    /* Allocate BSS segment */
    if (header.bss > 0) {
        if (peb_alloc_segment(peb, &peb->bss, header.bss,
                             P9_PERM_READ | P9_PERM_WRITE) < 0) {
            fprintf(stderr, "p9_load_executable_from_memory: bss alloc failed\n");
            peb_destroy(peb);
            return NULL;
        }
    }

    /* Load symbols from buffer */
    /* Note: This requires parsing variable-length symbol entries */
    /* For now, skip symbols from memory load */
    /* TODO: Implement symbol parsing from memory buffer */

    /* Setup stack */
    stack_size = header.spsz;
    if (stack_size == 0) {
        stack_size = 8 * 1024 * 1024;  /* Default 8 MB */
    }

    if (peb_setup_stack(peb, stack_size) < 0) {
        fprintf(stderr, "p9_load_executable_from_memory: stack setup failed\n");
        peb_destroy(peb);
        return NULL;
    }

    /* Setup virtual symbols */
    result = p9exe_setup_virtual_symbols(peb);
    if (result < 0) {
        fprintf(stderr, "p9_load_executable_from_memory: virtual symbols failed\n");
        /* Non-fatal, continue anyway */
    }

    /* Mark as active */
    peb->active = 1;

    fprintf(stderr, "p9_load_executable_from_memory: loaded %s successfully\n", cmd);

    return peb;
}
