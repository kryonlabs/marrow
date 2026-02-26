/*
 * Marrow /svc Filesystem Implementation
 * C89/C90 compliant
 *
 * Provides dynamic service listing and control via 9P
 */

#include "libregistry.h"
#include "lib9p.h"
#include <stdio.h>
#include <stdlib.h>
#include "compat.h"
#include <string.h>
#include <time.h>

/* External functions */
extern int service_list(ServiceInfo **services, int *count);
extern void service_discover_free(char **names, int count);
extern char **service_discover(const char *type, int *count);
extern ServiceRegistry g_registry;

/* Static buffer for discover output */
static char discover_buf[8192];
static int discover_buf_len = 0;

/*
 * Read handler for /svc/discover
 * Returns list of registered services
 */
static ssize_t svc_discover_read(char *buf, size_t count, uint64_t offset, void *data)
{
    ServiceInfo *services;
    int i, num_services;
    char *p;

    (void)data;

    /* Build discover buffer if not already done */
    if (discover_buf_len == 0) {
        p = discover_buf;

        /* Get all services */
        if (service_list(&services, &num_services) == 0) {
            for (i = 0; i < num_services; i++) {
                int remaining = sizeof(discover_buf) - (p - discover_buf);
                if (remaining > 0) {
                    p += snprintf(p, remaining,
                                 "%s %s %ld\n",
                                 services[i].name,
                                 services[i].type,
                                 (long)services[i].registered);
                }

                /* Free service info */
                free(services[i].name);
                free(services[i].type);
            }
            free(services);
        }

        discover_buf_len = p - discover_buf;
    }

    /* Return requested portion */
    if (offset >= (uint64_t)discover_buf_len) {
        return 0;
    }
    if (offset + count > (size_t)discover_buf_len) {
        count = discover_buf_len - offset;
    }
    memcpy(buf, discover_buf + offset, count);
    return count;
}

/*
 * Read handler for /svc/ctl (returns status)
 */
static ssize_t svc_ctl_read(char *buf, size_t count, uint64_t offset, void *data)
{
    static char status_buf[256];
    static int buf_filled = 0;
    size_t len;

    (void)data;

    if (!buf_filled) {
        snprintf(status_buf, sizeof(status_buf),
                 "Service Registry: %d services registered, %d mounts active\n",
                 g_registry.num_services,
                 g_registry.num_mounts);
        buf_filled = 1;
    }

    len = strlen(status_buf);
    if (offset >= len) {
        return 0;
    }
    if (offset + count > len) {
        count = len - offset;
    }
    memcpy(buf, status_buf + offset, count);
    return count;
}

/*
 * Write handler for /svc/ctl
 * Register/unregister services
 */
static ssize_t svc_ctl_write(const char *buf, size_t count, uint64_t offset, void *data)
{
    char cmd[256];
    char name[64], type[32];
    P9Node *root;
    P9Node *tree;

    (void)offset;
    (void)data;

    /* Copy to null-terminate */
    if (count >= sizeof(cmd)) {
        count = sizeof(cmd) - 1;
    }
    memcpy(cmd, buf, count);
    cmd[count] = '\0';

    /* Parse: "register name type" */
    if (sscanf(cmd, "register %63s %31s", name, type) == 2) {
        /* Create service directory */
        root = tree_root();
        if (root == NULL) {
            fprintf(stderr, "svc_ctl: no root tree\n");
            return -1;
        }

        tree = tree_create_dir(root, name);
        if (tree == NULL) {
            fprintf(stderr, "svc_ctl: failed to create tree for '%s'\n", name);
            return -1;
        }

        if (service_register(name, type, tree) < 0) {
            fprintf(stderr, "svc_ctl: failed to register '%s'\n", name);
            return -1;
        }

        fprintf(stderr, "svc_ctl: registered service '%s' (type=%s)\n", name, type);
        return count;
    }

    /* Parse: "unregister name" */
    if (sscanf(cmd, "unregister %63s", name) == 1) {
        if (service_unregister(name) < 0) {
            fprintf(stderr, "svc_ctl: failed to unregister '%s'\n", name);
            return -1;
        }
        return count;
    }

    fprintf(stderr, "svc_ctl: unknown command: %s\n", cmd);
    return -1;
}

/*
 * Initialize /svc filesystem
 */
int svc_init(P9Node *root)
{
    P9Node *svc_dir;
    P9Node *ctl_file;
    P9Node *discover_file;

    if (root == NULL) {
        fprintf(stderr, "svc_init: root is NULL\n");
        return -1;
    }

    /* Create /svc directory */
    svc_dir = tree_create_dir(root, "svc");
    if (svc_dir == NULL) {
        fprintf(stderr, "svc_init: failed to create /svc directory\n");
        return -1;
    }

    /* Create /svc/ctl - register/unregister services */
    ctl_file = tree_create_file(svc_dir, "ctl", NULL,
                                svc_ctl_read,
                                svc_ctl_write);
    if (ctl_file == NULL) {
        fprintf(stderr, "svc_init: failed to create /svc/ctl\n");
        return -1;
    }

    /* Create /svc/discover - list services */
    discover_file = tree_create_file(svc_dir, "discover", NULL,
                                      svc_discover_read,
                                      NULL);
    if (discover_file == NULL) {
        fprintf(stderr, "svc_init: failed to create /svc/discover\n");
        return -1;
    }

    fprintf(stderr, "svc_init: /svc filesystem initialized\n");
    return 0;
}
