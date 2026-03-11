/*
 * Auth Stub Implementation
 * Provides stub functions when auth modules are disabled
 */

#include <lib9.h>
#include <stddef.h>

/* Forward declarations for opaque types */
typedef struct P9anySession P9anySession;
typedef struct SecstoreSession SecstoreSession;

/*
 * Stub p9any handler - always returns failure
 */
int p9any_handler(int fd, const char *user, const char *password)
{
    /* P9any authentication disabled */
    (void)fd;
    (void)user;
    (void)password;
    return -1;
}

/*
 * Stub p9any session free - does nothing
 */
void p9any_session_free(P9anySession *s)
{
    /* P9any authentication disabled */
    (void)s;
}

/*
 * Stub secstore init - always returns failure
 */
int secstore_init(const char *secstore_dir)
{
    /* Secstore disabled */
    (void)secstore_dir;
    return -1;
}

/*
 * Stub secstore handler - always returns failure
 */
int secstore_handler(int fd, const char *user, const char *password)
{
    /* Secstore disabled */
    (void)fd;
    (void)user;
    (void)password;
    return -1;
}

/*
 * Stub secstore session free - does nothing
 */
void secstore_session_free(SecstoreSession *s)
{
    /* Secstore disabled */
    (void)s;
}
