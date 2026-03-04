/*
 * TaijiOS - Compiler Compatibility Header
 * Provides portable macros for GCC and Plan 9 compilers
 *
 * This header enables the codebase to compile with both:
 * - GCC/Clang on Linux/POSIX systems
 * - Plan 9 compilers (9c/9l/9a) via plan9port
 */

#ifndef P9_COMPAT_H
#define P9_COMPAT_H

/*
 * Compiler detection
 */
#if defined(__GNUC__) || defined(__clang__)
    #define P9_GCC_COMPAT 1
#else
    #define P9_GCC_COMPAT 0
#endif

/*
 * Portable function attributes
 */
#if P9_GCC_COMPAT
    #define P9_UNUSED __attribute__((unused))
    #define P9_INLINE static
#else
    /* Plan 9 compiler doesn't support attributes */
    #define P9_UNUSED
    #define P9_INLINE static
#endif

/*
 * Portable inline functions
 * C89 doesn't have 'inline', but both GCC and Plan 9 support static functions
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    #define P9_INLINE_C99 inline
#elif P9_GCC_COMPAT
    #define P9_INLINE_C99 static inline
#else
    /* Plan 9 and C89: use static */
    #define P9_INLINE_C99 static
#endif

/*
 * Format attributes for printf/scanf (GCC only)
 */
#if P9_GCC_COMPAT
    #define P9_PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
    #define P9_SCANF(fmt, args) __attribute__((format(scanf, fmt, args)))
#else
    #define P9_PRINTF(fmt, args)
    #define P9_SCANF(fmt, args)
#endif

/*
 * Packing/alignment attributes
 */
#if P9_GCC_COMPAT
    #define P9_PACKED __attribute__((packed))
    #define P9_ALIGN(n) __attribute__((aligned(n)))
#else
    #define P9_PACKED
    #define P9_ALIGN(n)
#endif

/*
 * Unused parameter marking
 */
#if P9_GCC_COMPAT
    #define P9_UNUSED_PARAM __attribute__((unused))
#else
    #define P9_UNUSED_PARAM
#endif

/*
 * Constructor/destructor attributes (GCC only)
 */
#if P9_GCC_COMPAT
    #define P9_CONSTRUCTOR __attribute__((constructor))
    #define P9_DESTRUCTOR __attribute__((destructor))
#else
    #define P9_CONSTRUCTOR
    #define P9_DESTRUCTOR
#endif

/*
 * Weak symbol support
 */
#if P9_GCC_COMPAT
    #define P9_WEAK __attribute__((weak))
#else
    #define P9_WEAK
#endif

/*
 * Macro to mark functions as deprecated (GCC only)
 */
#if P9_GCC_COMPAT
    #define P9_DEPRECATED(msg) __attribute__((deprecated(msg)))
#else
    #define P9_DEPRECATED(msg)
#endif

/*
 * Type alignment macros
 * Both GCC and Plan 9 need this for proper structure alignment
 */
#define P9_ALIGNOF(type) offsetof(struct { char c; type t; }, t)

#endif /* P9_COMPAT_H */
