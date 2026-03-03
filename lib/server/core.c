/*
 * Marrow Embedding API - Core Implementation
 * C89/C90 compliant
 *
 * Core instance management and lifecycle functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib9p.h"
#include "graphics.h"
#include "marrow_embed.h"

/* Complete MarrowInstance structure (internal) */
struct MarrowInstance {
    MarrowConfig config;
    int listen_fd;
    int running;
    void *screen;
    int screen_width;
    int screen_height;
    void *internal;
};

/* Forward declarations for internal functions */
int marrow_init_subsystems(MarrowInstance *instance);
void marrow_cleanup_subsystems(MarrowInstance *instance);
int marrow_server_start(MarrowInstance *instance);
void marrow_server_stop(MarrowInstance *instance);
void marrow_server_process_events(MarrowInstance *instance);
void marrow_server_run(MarrowInstance *instance);

/*
 * Default log callback
 */
static void default_log_callback(const char *msg, int level)
{
    const char *level_str;
    switch (level) {
        case MARROW_LOG_DEBUG: level_str = "DEBUG"; break;
        case MARROW_LOG_INFO:  level_str = "INFO"; break;
        case MARROW_LOG_WARN:  level_str = "WARN"; break;
        case MARROW_LOG_ERROR: level_str = "ERROR"; break;
        default:               level_str = "UNKNOWN"; break;
    }
    fprintf(stderr, "[marrow:%s] %s\n", level_str, msg);
}

/*
 * Create a new Marrow instance
 */
MarrowInstance* marrow_create(MarrowConfig *config)
{
    MarrowInstance *instance;

    if (config == NULL) {
        return NULL;
    }

    instance = (MarrowInstance *)malloc(sizeof(MarrowInstance));
    if (instance == NULL) {
        return NULL;
    }

    /* Copy configuration */
    memset(instance, 0, sizeof(MarrowInstance));
    memcpy(&instance->config, config, sizeof(MarrowConfig));

    /* Set defaults */
    if (instance->config.port == 0) {
        instance->config.port = 17010;
    }
    if (instance->config.screen_width == 0) {
        instance->config.screen_width = 800;
    }
    if (instance->config.screen_height == 0) {
        instance->config.screen_height = 1080;
    }

    /* Set default log callback if none provided */
    if (instance->config.log_callback == NULL) {
        instance->config.log_callback = default_log_callback;
    }

    /* Initialize state */
    instance->listen_fd = -1;
    instance->running = 0;
    instance->screen = NULL;
    instance->screen_width = instance->config.screen_width;
    instance->screen_height = instance->config.screen_height;
    instance->internal = NULL;

    return instance;
}

/*
 * Destroy a Marrow instance
 */
void marrow_destroy(MarrowInstance *instance)
{
    if (instance == NULL) {
        return;
    }

    /* Stop server if running */
    if (instance->running) {
        marrow_stop(instance);
    }

    /* Cleanup subsystems */
    marrow_cleanup_subsystems(instance);

    /* Free instance */
    free(instance);
}

/*
 * Start the Marrow server
 */
int marrow_start(MarrowInstance *instance)
{
    if (instance == NULL) {
        return -1;
    }

    if (instance->running) {
        /* Already running */
        return 0;
    }

    /* Initialize subsystems */
    if (marrow_init_subsystems(instance) < 0) {
        return -1;
    }

    /* Start TCP server */
    if (marrow_server_start(instance) < 0) {
        marrow_cleanup_subsystems(instance);
        return -1;
    }

    return 0;
}

/*
 * Stop the Marrow server
 */
void marrow_stop(MarrowInstance *instance)
{
    if (instance == NULL) {
        return;
    }

    if (!instance->running) {
        /* Not running */
        return;
    }

    /* Stop server */
    marrow_server_stop(instance);
}

/*
 * Check if the server is running
 */
int marrow_is_running(MarrowInstance *instance)
{
    if (instance == NULL) {
        return 0;
    }
    return instance->running;
}

/*
 * Get the screen buffer
 */
void* marrow_get_screen(MarrowInstance *instance)
{
    if (instance == NULL) {
        return NULL;
    }
    return instance->screen;
}

/*
 * Get screen dimensions
 */
int marrow_get_screen_size(MarrowInstance *instance, int *width, int *height)
{
    if (instance == NULL) {
        return -1;
    }

    if (width != NULL) {
        *width = instance->screen_width;
    }
    if (height != NULL) {
        *height = instance->screen_height;
    }

    return 0;
}

/*
 * Invalidate screen region
 */
void marrow_invalidate_region(MarrowInstance *instance,
                               int x, int y, int width, int height)
{
    /* TODO: Implement region invalidation */
    if (instance == NULL) {
        return;
    }
}

/*
 * Register a service
 */
int marrow_register_service(MarrowInstance *instance,
                            const char *name,
                            const char *type)
{
    /* TODO: Implement service registration */
    if (instance == NULL || name == NULL) {
        return -1;
    }
    return 0;
}

/*
 * Unregister a service
 */
int marrow_unregister_service(MarrowInstance *instance,
                              const char *name)
{
    /* TODO: Implement service unregistration */
    if (instance == NULL || name == NULL) {
        return -1;
    }
    return 0;
}

/*
 * Set event callback
 */
int marrow_set_event_callback(MarrowInstance *instance,
                               void (*callback)(void *userdata, const char *event),
                               void *userdata)
{
    if (instance == NULL) {
        return -1;
    }

    instance->config.event_callback = callback;
    instance->config.event_userdata = userdata;

    return 0;
}

/*
 * Get the server port
 */
int marrow_get_port(MarrowInstance *instance)
{
    if (instance == NULL) {
        return -1;
    }
    return instance->config.port;
}

/*
 * Process pending events
 */
void marrow_process_events(MarrowInstance *instance)
{
    if (instance == NULL || !instance->running) {
        return;
    }
    marrow_server_process_events(instance);
}

/*
 * Run the server event loop
 */
void marrow_run(MarrowInstance *instance)
{
    if (instance == NULL || !instance->running) {
        return;
    }
    marrow_server_run(instance);
}
