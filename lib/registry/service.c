/*
 * Marrow Service Registry Implementation
 * C89/C90 compliant
 *
 * Allows external services to register and provide 9P file trees
 * Thread-safe: Uses pthread rwlock for concurrent access
 */

#include "libregistry.h"
#include "lib9p.h"
#include <stdlib.h>
#include "compat.h"
#include <string.h>
#include <time.h>
#include <stdio.h>

/* Global registry */
ServiceRegistry g_registry = {0};

/*
 * Initialize service registry
 * Call once at startup
 */
int service_registry_init(void)
{
    int result;

    g_registry.services = NULL;
    g_registry.mounts = NULL;
    g_registry.num_services = 0;
    g_registry.num_mounts = 0;

    /* Initialize rwlock */
    result = pthread_rwlock_init(&g_registry.lock, NULL);
    if (result != 0) {
        fprintf(stderr, "service_registry_init: rwlock init failed\n");
        return -1;
    }

    fprintf(stderr, "service_registry: initialized (thread-safe)\n");
    return 0;
}

/*
 * Cleanup service registry
 * Call at shutdown
 */
void service_registry_cleanup(void)
{
    ServiceEntry *svc, *svc_next;
    MountEntry *mnt, *mnt_next;

    /* Acquire write lock for cleanup */
    pthread_rwlock_wrlock(&g_registry.lock);

    /* Free services */
    for (svc = g_registry.services; svc != NULL; svc = svc_next) {
        svc_next = svc->next;
        /* Don't free tree - owned by service */
        free(svc);
    }

    /* Free mounts */
    for (mnt = g_registry.mounts; mnt != NULL; mnt = mnt_next) {
        mnt_next = mnt->next;
        free(mnt);
    }

    g_registry.services = NULL;
    g_registry.mounts = NULL;
    g_registry.num_services = 0;
    g_registry.num_mounts = 0;

    pthread_rwlock_unlock(&g_registry.lock);

    /* Destroy rwlock */
    pthread_rwlock_destroy(&g_registry.lock);

    fprintf(stderr, "service_registry: cleaned up\n");
}

/*
 * Register a service with marrow
 */
int service_register(const char *name, const char *type, P9Node *tree)
{
    ServiceEntry *entry;

    if (name == NULL || type == NULL || tree == NULL) {
        fprintf(stderr, "service_register: invalid arguments\n");
        return -1;
    }

    /* Acquire write lock */
    pthread_rwlock_wrlock(&g_registry.lock);

    /* Check for duplicate name */
    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        if (strcmp(entry->name, name) == 0) {
            fprintf(stderr, "service_register: name '%s' already registered\n", name);
            pthread_rwlock_unlock(&g_registry.lock);
            return -1;
        }
    }

    /* Check limit */
    if (g_registry.num_services >= MAX_SERVICES) {
        fprintf(stderr, "service_register: too many services\n");
        pthread_rwlock_unlock(&g_registry.lock);
        return -1;
    }

    /* Create new entry */
    entry = (ServiceEntry *)calloc(1, sizeof(ServiceEntry));
    if (entry == NULL) {
        fprintf(stderr, "service_register: failed to allocate entry\n");
        pthread_rwlock_unlock(&g_registry.lock);
        return -1;
    }

    strncpy(entry->name, name, MAX_SERVICE_NAME - 1);
    strncpy(entry->type, type, MAX_SERVICE_TYPE - 1);
    entry->tree = tree;
    entry->registered = time(NULL);
    entry->client_fd = -1;
    entry->active = 1;

    /* Add to list */
    entry->next = g_registry.services;
    g_registry.services = entry;
    g_registry.num_services++;

    fprintf(stderr, "service_register: registered '%s' (type=%s)\n", name, type);

    pthread_rwlock_unlock(&g_registry.lock);
    return 0;
}

/*
 * Unregister a service
 */
int service_unregister(const char *name)
{
    ServiceEntry *entry, *prev;

    if (name == NULL) {
        return -1;
    }

    /* Acquire write lock */
    pthread_rwlock_wrlock(&g_registry.lock);

    prev = NULL;
    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        if (strcmp(entry->name, name) == 0) {
            /* Remove from list */
            if (prev == NULL) {
                g_registry.services = entry->next;
            } else {
                prev->next = entry->next;
            }
            g_registry.num_services--;

            pthread_rwlock_unlock(&g_registry.lock);

            /* TODO: Unmount any mounts for this service */

            free(entry);
            fprintf(stderr, "service_unregister: unregistered '%s'\n", name);
            return 0;
        }
        prev = entry;
    }

    pthread_rwlock_unlock(&g_registry.lock);

    fprintf(stderr, "service_unregister: service '%s' not found\n", name);
    return -1;
}

/*
 * Discover services by type
 */
char **service_discover(const char *type, int *count)
{
    ServiceEntry *entry;
    char **names;
    int n, i;

    if (count == NULL) {
        return NULL;
    }

    /* Acquire read lock */
    pthread_rwlock_rdlock(&g_registry.lock);

    /* Count matching services */
    n = 0;
    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        if (type == NULL || strcmp(entry->type, type) == 0) {
            n++;
        }
    }

    if (n == 0) {
        pthread_rwlock_unlock(&g_registry.lock);
        *count = 0;
        return NULL;
    }

    /* Allocate array */
    names = (char **)calloc(n, sizeof(char *));
    if (names == NULL) {
        pthread_rwlock_unlock(&g_registry.lock);
        *count = 0;
        return NULL;
    }

    /* Fill array */
    i = 0;
    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        if (type == NULL || strcmp(entry->type, type) == 0) {
            names[i] = strdup(entry->name);
            if (names[i] == NULL) {
                /* Cleanup on error */
                pthread_rwlock_unlock(&g_registry.lock);
                for (i--; i >= 0; i--) {
                    free(names[i]);
                }
                free(names);
                *count = 0;
                return NULL;
            }
            i++;
        }
    }

    pthread_rwlock_unlock(&g_registry.lock);

    *count = n;
    return names;
}

/*
 * Free result from service_discover
 */
void service_discover_free(char **names, int count)
{
    int i;
    if (names == NULL) return;
    for (i = 0; i < count; i++) {
        free(names[i]);
    }
    free(names);
}

/*
 * Get service information
 */
ServiceInfo *service_get(const char *name)
{
    ServiceEntry *entry;
    ServiceInfo *info;

    if (name == NULL) {
        return NULL;
    }

    /* Acquire read lock */
    pthread_rwlock_rdlock(&g_registry.lock);

    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        if (strcmp(entry->name, name) == 0) {
            info = (ServiceInfo *)malloc(sizeof(ServiceInfo));
            if (info == NULL) {
                pthread_rwlock_unlock(&g_registry.lock);
                return NULL;
            }
            info->name = strdup(entry->name);
            info->type = strdup(entry->type);
            info->tree = entry->tree;
            info->registered = entry->registered;
            info->client_fd = entry->client_fd;

            pthread_rwlock_unlock(&g_registry.lock);
            return info;
        }
    }

    pthread_rwlock_unlock(&g_registry.lock);
    return NULL;
}

/*
 * Free service information
 */
void service_free_info(ServiceInfo *info)
{
    if (info == NULL) return;
    free(info->name);
    free(info->type);
    free(info);
}

/*
 * List all services
 */
int service_list(ServiceInfo **services, int *count)
{
    ServiceEntry *entry;
    ServiceInfo *info_array;
    int i;

    if (services == NULL || count == NULL) {
        return -1;
    }

    /* Acquire read lock */
    pthread_rwlock_rdlock(&g_registry.lock);

    if (g_registry.num_services == 0) {
        *services = NULL;
        *count = 0;
        pthread_rwlock_unlock(&g_registry.lock);
        return 0;
    }

    /* Allocate array */
    info_array = (ServiceInfo *)calloc(g_registry.num_services, sizeof(ServiceInfo));
    if (info_array == NULL) {
        *count = 0;
        pthread_rwlock_unlock(&g_registry.lock);
        return -1;
    }

    /* Fill array */
    i = 0;
    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        info_array[i].name = strdup(entry->name);
        info_array[i].type = strdup(entry->type);
        info_array[i].tree = entry->tree;
        info_array[i].registered = entry->registered;
        info_array[i].client_fd = entry->client_fd;
        i++;
    }

    pthread_rwlock_unlock(&g_registry.lock);

    *services = info_array;
    *count = g_registry.num_services;
    return 0;
}

/*
 * Find service by client file descriptor
 */
ServiceEntry* find_service_by_client(int client_fd)
{
    ServiceEntry *entry;

    /* Acquire read lock */
    pthread_rwlock_rdlock(&g_registry.lock);

    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        if (entry->client_fd == client_fd) {
            pthread_rwlock_unlock(&g_registry.lock);
            return entry;
        }
    }

    pthread_rwlock_unlock(&g_registry.lock);
    return NULL;
}

/*
 * Set client_fd for a service by name
 * Called after service registration to associate with a client
 */
int service_set_client_fd(const char *name, int client_fd)
{
    ServiceEntry *entry;

    if (name == NULL) {
        return -1;
    }

    /* Acquire read lock */
    pthread_rwlock_rdlock(&g_registry.lock);

    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        if (strcmp(entry->name, name) == 0) {
            entry->client_fd = client_fd;
            pthread_rwlock_unlock(&g_registry.lock);
            return 0;
        }
    }

    pthread_rwlock_unlock(&g_registry.lock);
    return -1;
}

/*
 * Get service tree for a client
 * Returns the tree associated with a client connection
 */
P9Node* service_get_tree_by_client(int client_fd)
{
    ServiceEntry *entry;
    P9Node *tree = NULL;

    /* Acquire read lock */
    pthread_rwlock_rdlock(&g_registry.lock);

    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        if (entry->client_fd == client_fd) {
            tree = entry->tree;
            break;
        }
    }

    pthread_rwlock_unlock(&g_registry.lock);
    return tree;
}
