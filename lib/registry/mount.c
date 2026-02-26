/*
 * Marrow Namespace Mounting Implementation
 * C89/C90 compliant
 *
 * Allows services to mount their file trees into marrow's namespace
 */

#include "libregistry.h"
#include "lib9p.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* External global registry */
extern ServiceRegistry g_registry;

/*
 * Mount a service tree into namespace
 */
int namespace_mount(const char *path, P9Node *tree)
{
    MountEntry *entry;
    P9Node *parent;
    char *slash;
    char parent_path[MAX_MOUNT_PATH];

    if (path == NULL || tree == NULL) {
        fprintf(stderr, "namespace_mount: invalid arguments\n");
        return -1;
    }

    /* Check if path already mounted */
    for (entry = g_registry.mounts; entry != NULL; entry = entry->next) {
        if (strcmp(entry->path, path) == 0) {
            fprintf(stderr, "namespace_mount: path '%s' already mounted\n", path);
            return -1;
        }
    }

    /* Check limit */
    if (g_registry.num_mounts >= MAX_MOUNTS) {
        fprintf(stderr, "namespace_mount: too many mounts\n");
        return -1;
    }

    /* Find parent directory */
    strncpy(parent_path, path, sizeof(parent_path) - 1);
    slash = strrchr(parent_path, '/');
    if (slash != NULL && slash != parent_path) {
        *slash = '\0';
        parent = tree_lookup(tree_root(), parent_path);
    } else {
        parent = tree_root();
    }

    if (parent == NULL) {
        fprintf(stderr, "namespace_mount: parent not found for '%s'\n", path);
        return -1;
    }

    /* Create mount entry */
    entry = (MountEntry *)calloc(1, sizeof(MountEntry));
    if (entry == NULL) {
        fprintf(stderr, "namespace_mount: failed to allocate entry\n");
        return -1;
    }

    strncpy(entry->path, path, MAX_MOUNT_PATH - 1);
    entry->tree = tree;
    entry->service_fd = -1;

    /* Add to mount table */
    entry->next = g_registry.mounts;
    g_registry.mounts = entry;
    g_registry.num_mounts++;

    fprintf(stderr, "namespace_mount: mounted tree at '%s'\n", path);
    return 0;
}

/*
 * Unmount a service tree
 */
int namespace_unmount(const char *path)
{
    MountEntry *entry, *prev;

    if (path == NULL) {
        return -1;
    }

    prev = NULL;
    for (entry = g_registry.mounts; entry != NULL; entry = entry->next) {
        if (strcmp(entry->path, path) == 0) {
            /* Remove from list */
            if (prev == NULL) {
                g_registry.mounts = entry->next;
            } else {
                prev->next = entry->next;
            }
            g_registry.num_mounts--;
            free(entry);
            fprintf(stderr, "namespace_unmount: unmounted '%s'\n", path);
            return 0;
        }
        prev = entry;
    }

    fprintf(stderr, "namespace_unmount: path '%s' not mounted\n", path);
    return -1;
}
