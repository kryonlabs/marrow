#ifndef P9EXEC_H
#define P9EXEC_H

#include "runtime/peb.h"
#include <stdint.h>
#include <stdio.h>

/*
 * Plan 9 Executable Loader
 * C89/C90 compliant
 *
 * This module loads Plan 9 executables (6l/8l/5l output format)
 * into memory and prepares them for execution.
 */

/*
 * Plan 9 executable header (32 bytes)
 * From Plan 9's 6l/8l/5l linker output format
 */
typedef struct {
    uint32_t magic;    /* Magic number (0x8E for amd64, 0x7D for i386) */
    uint32_t text;     /* Text segment size */
    uint32_t data;     /* Data segment size */
    uint32_t bss;      /* BSS segment size */
    uint32_t syms;     /* Symbol table size */
    uint32_t entry;    /* Entry point */
    uint32_t spsz;     /* Stack size */
    uint32_t pcsz;     /* PC size (unused in modern linkers) */
} P9Header;

/*
 * Magic numbers for different architectures
 */
#define P9_MAGIC_AMD64   0x8E    /* 6l output */
#define P9_MAGIC_I386    0x7D    /* 8l output */
#define P9_MAGIC_ARM64   0x8C    /* 5l output (not supported yet) */

/*
 * Symbol types (from Plan 9/obj.h)
 */
#define P9_SYM_TEXT     'T'
#define P9_SYM_DATA     'D'
#define P9_SYM_BSS      'B'
#define P9_SYM_FILE     'f'
#define P9_SYM_UNDEF    'U'
#define P9_SYM_EXTERN  ' '

/*
 * Loader API
 */

/*
 * Initialize the loader module
 * Must be called before using any other loader functions
 * Returns 0 on success, -1 on error
 */
int p9_loader_init(void);

/*
 * Cleanup the loader module
 */
void p9_loader_cleanup(void);

/*
 * Load a Plan 9 executable from a file
 *
 * Parameters:
 *   path   - Path to the Plan 9 executable
 *   cmd    - Command name (for display)
 *
 * Returns:
 *   PEB pointer on success
 *   NULL on error
 *
 * The returned PEB is fully initialized with:
 * - All segments loaded into memory with correct permissions
 * - Symbol table populated
 * - Entry point set
 * - Stack allocated
 * - Registers initialized
 */
PEB *p9_load_executable(const char *path, const char *cmd);

/*
 * Load a Plan 9 executable from memory buffer
 *
 * Parameters:
 *   buffer - Pointer to executable data in memory
 *   size   - Size of the buffer
 *   cmd    - Command name (for display)
 *
 * Returns:
 *   PEB pointer on success
 *   NULL on error
 */
PEB *p9_load_executable_from_memory(const uint8_t *buffer, size_t size,
                                    const char *cmd);

/*
 * Validate a Plan 9 executable header
 *
 * Parameters:
 *   header - Pointer to header to validate
 *
 * Returns:
 *   1 if valid, 0 if invalid
 */
int p9exe_validate_header(const P9Header *header);

/*
 * Parse the Plan 9 executable header
 *
 * Parameters:
 *   fp     - Open file pointer positioned at header
 *   header - Output header structure
 *
 * Returns:
 *   0 on success, -1 on error
 */
int p9exe_parse_header(FILE *fp, P9Header *header);

/*
 * Load segments from executable
 *
 * Parameters:
 *   fp     - Open file pointer
 *   peb    - PEB to load segments into
 *   header - Parsed header
 *
 * Returns:
 *   0 on success, -1 on error
 */
int p9exe_load_segments(FILE *fp, PEB *peb, const P9Header *header);

/*
 * Load symbol table from executable
 *
 * Parameters:
 *   fp     - Open file pointer
 *   peb    - PEB to load symbols into
 *   header - Parsed header
 *
 * Returns:
 *   0 on success, -1 on error
 */
int p9exe_load_symbols(FILE *fp, PEB *peb, const P9Header *header);

/*
 * Setup virtual symbols (C functions callable from Plan 9 assembly)
 *
 * Parameters:
 *   peb - PEB to add virtual symbols to
 *
 * Returns:
 *   0 on success, -1 on error
 */
int p9exe_setup_virtual_symbols(PEB *peb);

/*
 * Print executable information for debugging
 *
 * Parameters:
 *   header - Validated header
 */
void p9exe_print_header_info(const P9Header *header);

#endif /* P9EXEC_H */
