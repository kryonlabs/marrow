/*
 * Marrow Embedding Example
 * C89/C90 compliant
 *
 * This example demonstrates how to embed Marrow in a standalone application.
 * The app will:
 * 1. Create a Marrow instance
 * 2. Start the 9P server
 * 3. Draw to the screen buffer
 * 4. Handle events
 * 5. Clean up
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "marrow_embed.h"

/* Simple event callback */
static void my_event_callback(void *userdata, const char *event)
{
    printf("Event: %s\n", event);
}

/* Simple log callback */
static void my_log_callback(const char *msg, int level)
{
    const char *level_str = "INFO";
    switch (level) {
        case MARROW_LOG_DEBUG: level_str = "DEBUG"; break;
        case MARROW_LOG_INFO:  level_str = "INFO"; break;
        case MARROW_LOG_WARN:  level_str = "WARN"; break;
        case MARROW_LOG_ERROR: level_str = "ERROR"; break;
    }
    printf("[%s] %s\n", level_str, msg);
}

int main(int argc, char **argv)
{
    MarrowInstance *marrow;
    MarrowConfig config;
    int result = 0;

    /* Initialize configuration */
    memset(&config, 0, sizeof(config));
    config.app_name = "embed-example";
    config.app_version = "1.0.0";
    config.port = 17010;
    config.screen_width = 800;
    config.screen_height = 600;
    config.enable_cpu_server = 0;
    config.enable_auth = 1;
    config.enable_namespace = 0;
    config.keys_path = NULL;
    config.log_callback = my_log_callback;
    config.event_callback = my_event_callback;
    config.event_userdata = NULL;

    printf("Marrow Embedding Example\n");
    printf("=======================\n");
    printf("Creating Marrow instance...\n");

    /* Create Marrow instance */
    marrow = marrow_create(&config);
    if (marrow == NULL) {
        fprintf(stderr, "Error: failed to create Marrow instance\n");
        return 1;
    }

    printf("Starting Marrow server...\n");

    /* Start the server */
    if (marrow_start(marrow) < 0) {
        fprintf(stderr, "Error: failed to start Marrow server\n");
        result = 1;
        goto cleanup;
    }

    printf("Server running on port %d\n", marrow_get_port(marrow));
    printf("Screen: %dx%d\n", config.screen_width, config.screen_height);
    printf("\n");
    printf("Connect with: 9p -a 'tcp!localhost!%d' ls /\n", marrow_get_port(marrow));
    printf("\n");
    printf("Press Ctrl-C to stop...\n");

    /* Run the server (blocking) */
    /* In a real app, you would use marrow_process_events() in your own loop */
    marrow_run(marrow);

    printf("\nServer stopped.\n");

cleanup:
    /* Clean up */
    printf("Cleaning up...\n");
    marrow_destroy(marrow);
    printf("Done.\n");

    return result;
}
