/*
 * Marrow Service Discovery Implementation
 * C89/C90 compliant
 */

#include "libregistry.h"
#include "lib9p.h"
#include "compat.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* External global registry */
extern ServiceRegistry g_registry;

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
