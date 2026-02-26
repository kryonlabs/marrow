#ifndef LIBREGISTRY_H
#define LIBREGISTRY_H

#include "lib9p.h"
#include <pthread.h>

/*
 * Service Registry API
 * Allows external services (like kryon) to register with marrow
 * Thread-safe: Uses pthread rwlock for concurrent access
 */

/*
 * Service Registry API
 * Allows external services (like kryon) to register with marrow
 */

/* Constants */
#define MAX_SERVICES 64
#define MAX_SERVICE_NAME 64
#define MAX_SERVICE_TYPE 32
#define MAX_MOUNTS 128
#define MAX_MOUNT_PATH 256

/*
 * Service information structure
 */
typedef struct ServiceInfo {
    char *name;
    char *type;
    P9Node *tree;
    time_t registered;
    int client_fd;
} ServiceInfo;

/*
 * Internal registry entries
 */
typedef struct ServiceEntry {
    char name[MAX_SERVICE_NAME];
    char type[MAX_SERVICE_TYPE];
    P9Node *tree;
    time_t registered;
    int client_fd;
    int active;
    struct ServiceEntry *next;
} ServiceEntry;

typedef struct MountEntry {
    char path[MAX_MOUNT_PATH];
    P9Node *tree;
    int service_fd;
    struct MountEntry *next;
} MountEntry;

typedef struct ServiceRegistry {
    ServiceEntry *services;
    MountEntry *mounts;
    int num_services;
    int num_mounts;
    pthread_rwlock_t lock;  /* RW lock for concurrent access */
} ServiceRegistry;

/* Registry initialization */
int service_registry_init(void);
void service_registry_cleanup(void);

/* Service registration */
int service_register(const char *name, const char *type, P9Node *tree);
int service_unregister(const char *name);

/* Service discovery */
char **service_discover(const char *type, int *count);
void service_discover_free(char **names, int count);

/* Service information */
ServiceInfo *service_get(const char *name);
void service_free_info(ServiceInfo *info);
int service_list(ServiceInfo **services, int *count);

/* Namespace mounting */
int namespace_mount(const char *path, P9Node *tree);
int namespace_unmount(const char *path);

/*
 * Service mounting from connected clients
 * These functions track mounts by client_fd for automatic cleanup
 */
int service_mount_from_client(int client_fd, const char *name,
                             const char *path, P9Node *tree);
int service_unmount_by_client(int client_fd);
ServiceEntry* find_service_by_client(int client_fd);
int service_set_client_fd(const char *name, int client_fd);
P9Node* service_get_tree_by_client(int client_fd);

/* /svc filesystem */
int svc_init(P9Node *root);

#endif /* LIBREGISTRY_H */
