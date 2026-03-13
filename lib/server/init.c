/*
 * Mu Embedding API - Initialization
 * C89/C90 compliant
 *
 * Extracted from cmd/mu/main.c initialization sequence
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include "lib9p.h"
#include "libregistry.h"
#include "graphics.h"
#include "../include/auth_dp9ik.h"
#include "../include/auth_p9any.h"
#include "../include/devfactotum.h"
#include "../include/secstore.h"
#include "../include/devenv.h"
#include "../include/devfd.h"
#include "../include/devproc.h"
#include "../include/devsound.h"
#include "../include/cpu_server.h"
#include "../include/namespace.h"
#include "../include/ctl.h"
#include "platform/socket.h"

#include "marrow_embed.h"

/* Complete MarrowInstance structure (must match core.c) */
struct MarrowInstance {
    MarrowConfig config;
    int listen_fd;
    int running;
    void *screen;
    int screen_width;
    int screen_height;
    void *internal;
};

/* External device initialization functions (no headers available) */
extern int devcons_init(P9Node *dev_dir);
extern int devfd_init(P9Node *dev_dir);
extern int devproc_init(P9Node *root);
extern int devmouse_init(P9Node *dev_dir);
extern int devkbd_init(P9Node *dev_dir);
extern int devaudio_init(P9Node *dev_dir);
extern int devdraw_new_init(P9Node *draw_dir);
extern int devtime_init(P9Node *dev_dir);
extern int devrendezvous_init(P9Node *dev_dir);
extern int svc_init(P9Node *root);

/*
 * Initialize Marrow subsystems
 * Returns 0 on success, -1 on error
 */
int marrow_init_subsystems(MarrowInstance *instance)
{
    P9Node *root;
    P9Node *dev_dir;
    Rectangle screen_rect;
    Memimage *screen;

    if (instance == NULL) {
        return -1;
    }

    /* Log initialization start */
    if (instance->config.log_callback) {
        instance->config.log_callback("Initializing Marrow subsystems...", MARROW_LOG_INFO);
    }

    /* Initialize file tree */
    if (tree_init() < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize file tree", MARROW_LOG_ERROR);
        }
        return -1;
    }

    /* Initialize FID table */
    if (fid_init() < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize FID table", MARROW_LOG_ERROR);
        }
        return -1;
    }

    /* Initialize authentication (if enabled) */
    if (instance->config.enable_auth) {
        if (auth_session_init() < 0) {
            if (instance->config.log_callback) {
                instance->config.log_callback("Failed to initialize auth sessions", MARROW_LOG_WARN);
            }
        }

        root = tree_root();
        if (root != NULL) {
            if (factotum_init(root) < 0) {
                if (instance->config.log_callback) {
                    instance->config.log_callback("Failed to initialize factotum", MARROW_LOG_WARN);
                }
            }

            if (secstore_init(root) < 0) {
                if (instance->config.log_callback) {
                    instance->config.log_callback("Failed to initialize secstore", MARROW_LOG_WARN);
                }
            }

            /* Load default keys */
            if (instance->config.keys_path != NULL) {
                if (factotum_load_keys(instance->config.keys_path) < 0) {
                    /* Create default test user */
                    factotum_add_key("key proto=dp9ik dom=localhost user=glenda !password=glenda");
                    if (instance->config.log_callback) {
                        instance->config.log_callback("Using default test keys", MARROW_LOG_INFO);
                    }
                }
            } else {
                /* Create default test user */
                factotum_add_key("key proto=dp9ik dom=localhost user=glenda !password=glenda");
            }
        }
    }

    /* Initialize namespace (if enabled) */
    if (instance->config.enable_namespace) {
        if (namespace_init() < 0) {
            if (instance->config.log_callback) {
                instance->config.log_callback("Failed to initialize namespace manager", MARROW_LOG_ERROR);
            }
            return -1;
        }
    }

    /* Get root node */
    root = tree_root();
    if (root == NULL) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to get root node", MARROW_LOG_ERROR);
        }
        return -1;
    }

    /* Initialize CPU server (if enabled) */
    if (instance->config.enable_cpu_server) {
        if (cpu_server_init(root) < 0) {
            if (instance->config.log_callback) {
                instance->config.log_callback("Failed to initialize CPU server", MARROW_LOG_WARN);
            }
        }
    }

    /* Initialize service registry */
    if (service_registry_init() < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize service registry", MARROW_LOG_WARN);
        }
    }

    /* Create /dev directory */
    dev_dir = tree_create_dir(root, "dev");
    if (dev_dir == NULL) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to create /dev directory", MARROW_LOG_ERROR);
        }
        return -1;
    }

    /* Initialize system devices */
    if (devcons_init(dev_dir) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize /dev/cons", MARROW_LOG_WARN);
        }
    }

    if (devfd_init(dev_dir) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize /dev/fd", MARROW_LOG_WARN);
        }
    }

    if (devproc_init(root) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize /proc", MARROW_LOG_WARN);
        }
    }

    if (devenv_init(root) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize /env", MARROW_LOG_WARN);
        }
    }

    /* Initialize graphics - create screen buffer */
    screen_rect = Rect(0, 0, instance->config.screen_width, instance->config.screen_height);
    screen = memimage_alloc(screen_rect, RGBA32);
    if (screen == NULL) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to allocate screen", MARROW_LOG_ERROR);
        }
        return -1;
    }

    instance->screen = screen;

    /* Clear screen to dark blue */
    memfillcolor(screen, 0xFF121212);

    /* Initialize draw connection system */
    if (drawconn_init(screen) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize draw connection system", MARROW_LOG_WARN);
        }
    }

    /* Create /dev/draw directory */
    {
        P9Node *draw_dir = tree_create_dir(dev_dir, "draw");
        if (draw_dir != NULL) {
            if (devdraw_new_init(draw_dir) < 0) {
                if (instance->config.log_callback) {
                    instance->config.log_callback("Failed to initialize /dev/draw/new", MARROW_LOG_WARN);
                }
            }
        }
    }

    /* Initialize graphics devices */
    if (devscreen_init(dev_dir, (Memimage *)screen) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize /dev/screen", MARROW_LOG_WARN);
        }
    }

    if (devmouse_init(dev_dir) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize /dev/mouse", MARROW_LOG_WARN);
        }
    }

    if (devkbd_init(dev_dir) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize /dev/kbd", MARROW_LOG_WARN);
        }
    }

    if (devaudio_init(dev_dir) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize /dev/audio", MARROW_LOG_WARN);
        }
    }

    if (devtime_init(dev_dir) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize /dev/time", MARROW_LOG_WARN);
        }
    }

    if (devrendezvous_init(dev_dir) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize /dev/rendezvous", MARROW_LOG_WARN);
        }
    }

    /* Create /mnt directory */
    {
        P9Node *mnt_node = tree_walk(root, "mnt");
        if (mnt_node == NULL) {
            mnt_node = tree_create_dir(root, "mnt");
            if (mnt_node == NULL) {
                if (instance->config.log_callback) {
                    instance->config.log_callback("Failed to create /mnt", MARROW_LOG_ERROR);
                }
                return -1;
            }
        }
    }

    /* Initialize /svc filesystem */
    if (svc_init(root) < 0) {
        if (instance->config.log_callback) {
            instance->config.log_callback("Failed to initialize /svc filesystem", MARROW_LOG_WARN);
        }
    }

    return 0;
}

/*
 * Cleanup Marrow subsystems
 */
void marrow_cleanup_subsystems(MarrowInstance *instance)
{
    if (instance == NULL) {
        return;
    }

    if (instance->config.log_callback) {
        instance->config.log_callback("Cleaning up Marrow subsystems...", MARROW_LOG_INFO);
    }

    /* Free screen buffer */
    if (instance->screen != NULL) {
        free(instance->screen);
        instance->screen = NULL;
    }

    /* Note: Other subsystems don't have explicit cleanup functions yet */
    /* They will be cleaned up when the process exits */
}
