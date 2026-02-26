/*
 * Marrow Service Registry Implementation
 * C89/C90 compliant
 *
 * Allows external services to register and provide 9P file trees
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
    g_registry.services = NULL;
    g_registry.mounts = NULL;
    g_registry.num_services = 0;
    g_registry.num_mounts = 0;

    fprintf(stderr, "service_registry: initialized\n");
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

    /* Check for duplicate name */
    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        if (strcmp(entry->name, name) == 0) {
            fprintf(stderr, "service_register: name '%s' already registered\n", name);
            return -1;
        }
    }

    /* Check limit */
    if (g_registry.num_services >= MAX_SERVICES) {
        fprintf(stderr, "service_register: too many services\n");
        return -1;
    }

    /* Create new entry */
    entry = (ServiceEntry *)calloc(1, sizeof(ServiceEntry));
    if (entry == NULL) {
        fprintf(stderr, "service_register: failed to allocate entry\n");
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

            /* TODO: Unmount any mounts for this service */

            free(entry);
            fprintf(stderr, "service_unregister: unregistered '%s'\n", name);
            return 0;
        }
        prev = entry;
    }

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

    /* Count matching services */
    n = 0;
    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        if (type == NULL || strcmp(entry->type, type) == 0) {
            n++;
        }
    }

    if (n == 0) {
        *count = 0;
        return NULL;
    }

    /* Allocate array */
    names = (char **)calloc(n, sizeof(char *));
    if (names == NULL) {
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

    for (entry = g_registry.services; entry != NULL; entry = entry->next) {
        if (strcmp(entry->name, name) == 0) {
            info = (ServiceInfo *)malloc(sizeof(ServiceInfo));
            if (info == NULL) {
                return NULL;
            }
            info->name = strdup(entry->name);
            info->type = strdup(entry->type);
            info->tree = entry->tree;
            info->registered = entry->registered;
            info->client_fd = entry->client_fd;
            return info;
        }
    }

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

    if (g_registry.num_services == 0) {
        *services = NULL;
        *count = 0;
        return 0;
    }

    /* Allocate array */
    info_array = (ServiceInfo *)calloc(g_registry.num_services, sizeof(ServiceInfo));
    if (info_array == NULL) {
        *count = 0;
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

    *services = info_array;
    *count = g_registry.num_services;
    return 0;
}
