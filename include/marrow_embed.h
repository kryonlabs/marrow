/*
 * Marrow Embedding API
 * C89/C90 compliant
 *
 * This header defines the public API for embedding Marrow in applications.
 * Applications can link against libmarrow_embed.a to bundle Marrow directly.
 *
 * Usage:
 *   1. Create a MarrowConfig with desired settings
 *   2. Call marrow_create() to create an instance
 *   3. Call marrow_start() to start the server
 *   4. Use marrow_get_screen() for rendering
 *   5. Call marrow_stop() and marrow_destroy() when done
 */

#ifndef MARROW_EMBED_H
#define MARROW_EMBED_H

#include <stddef.h>

/* Forward declarations */
typedef struct MarrowInstance MarrowInstance;

/*
 * Configuration for Marrow instance
 */
typedef struct MarrowConfig {
    const char *app_name;         /* Application name (for logging) */
    const char *app_version;      /* Application version */
    int port;                     /* 9P server port (0 for auto) */
    int screen_width;             /* Screen width (default: 800) */
    int screen_height;            /* Screen height (default: 600) */
    int enable_cpu_server;        /* Enable CPU server (default: 0) */
    int enable_auth;              /* Enable authentication (default: 1) */
    int enable_namespace;         /* Enable namespace manager (default: 0) */
    const char *keys_path;        /* Path to keys file (NULL for default) */

    /* Logging callback (optional) */
    void (*log_callback)(const char *msg, int level);

    /* Event callback (optional) */
    void (*event_callback)(void *userdata, const char *event);
    void *event_userdata;
} MarrowConfig;

/*
 * Log levels for log_callback
 */
#define MARROW_LOG_DEBUG  0
#define MARROW_LOG_INFO   1
#define MARROW_LOG_WARN   2
#define MARROW_LOG_ERROR  3

/*
 * Create a new Marrow instance
 *
 * Returns a pointer to a MarrowInstance on success, NULL on failure.
 * The caller is responsible for calling marrow_destroy() when done.
 */
MarrowInstance* marrow_create(MarrowConfig *config);

/*
 * Destroy a Marrow instance
 *
 * Stops the server if running and frees all resources.
 */
void marrow_destroy(MarrowInstance *instance);

/*
 * Start the Marrow server
 *
 * Starts the 9P server on the configured port.
 * Returns 0 on success, -1 on failure.
 */
int marrow_start(MarrowInstance *instance);

/*
 * Stop the Marrow server
 *
 * Stops the 9P server. The instance can be restarted with marrow_start().
 */
void marrow_stop(MarrowInstance *instance);

/*
 * Check if the server is running
 *
 * Returns 1 if running, 0 otherwise.
 */
int marrow_is_running(MarrowInstance *instance);

/*
 * Get the screen buffer for rendering
 *
 * Returns a pointer to the screen buffer (RGBA32 format).
 * The buffer is screen_width * screen_height * 4 bytes.
 */
void* marrow_get_screen(MarrowInstance *instance);

/*
 * Get screen dimensions
 *
 * Fills in width and height with the current screen size.
 * Returns 0 on success, -1 on failure.
 */
int marrow_get_screen_size(MarrowInstance *instance, int *width, int *height);

/*
 * Invalidate screen region
 *
 * Marks a region as dirty, causing it to be sent to clients.
 * x, y: top-left corner
 * width, height: region size
 */
void marrow_invalidate_region(MarrowInstance *instance,
                               int x, int y, int width, int height);

/*
 * Register a service
 *
 * Registers a 9P service with the server.
 * Returns 0 on success, -1 on failure.
 */
int marrow_register_service(MarrowInstance *instance,
                            const char *name,
                            const char *type);

/*
 * Unregister a service
 *
 * Unregisters a previously registered service.
 * Returns 0 on success, -1 on failure.
 */
int marrow_unregister_service(MarrowInstance *instance,
                              const char *name);

/*
 * Set event callback
 *
 * Sets a callback function to receive events from Marrow.
 * Events include: client connect/disconnect, service changes, etc.
 */
int marrow_set_event_callback(MarrowInstance *instance,
                               void (*callback)(void *userdata, const char *event),
                               void *userdata);

/*
 * Get the server port
 *
 * Returns the port the server is listening on (useful if port was 0).
 */
int marrow_get_port(MarrowInstance *instance);

/*
 * Process pending events (non-blocking)
 *
 * Processes any pending 9P requests and events.
 * Call this regularly in your main loop.
 */
void marrow_process_events(MarrowInstance *instance);

/*
 * Run the server event loop (blocking)
 *
 * Blocks until marrow_stop() is called from another thread.
 * Returns when the server stops.
 */
void marrow_run(MarrowInstance *instance);

#endif /* MARROW_EMBED_H */
