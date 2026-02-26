#ifndef COMPAT_H
#define COMPAT_H

#include <stddef.h>
#include <stdint.h>

/*
 * C89/C90 compatibility declarations for POSIX functions
 * These are not part of C89 but are available on Linux systems
 */

/*
 * String functions (POSIX)
 */
#ifndef HAVE_STRDUP
extern char *strdup(const char *s);
#endif

#ifndef HAVE_STRDUP_R
extern char *strtok_r(char *str, const char *delim, char **saveptr);
#endif

/*
 * Formatted output (C99, but widely available)
 */
#ifndef HAVE_SNPRINTF
extern int snprintf(char *str, size_t size, const char *format, ...);
#endif

/*
 * Environment functions (POSIX)
 */
#ifndef HAVE_SETENV
extern int setenv(const char *name, const char *value, int overwrite);
#endif

#ifndef HAVE_UNSETENV
extern int unsetenv(const char *name);
#endif

#ifndef HAVE_PUTENV
extern int putenv(char *string);
#endif

/*
 * Process control (POSIX)
 */
#ifndef HAVE_KILL
extern int kill(int pid, int sig);
#endif

#endif /* COMPAT_H */
