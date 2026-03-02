/*
 * Marrow Embedding API - Server Implementation
 * C89/C90 compliant
 *
 * TCP server, client management, and event loop
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>

#include "lib9p.h"
#include "../platform/socket.h"
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

/* Maximum clients */
#define MAX_CLIENTS  64

/* Client information */
typedef struct ClientInfo {
    int fd;
    int auth_done;
} ClientInfo;

/* Server state */
static int g_listen_fd = -1;
static ClientInfo g_clients[MAX_CLIENTS];
static int g_nclients = 0;
static volatile sig_atomic_t g_running = 0;

/*
 * Signal handler for graceful shutdown
 */
static void signal_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) {
        g_running = 0;
    }
}

/*
 * Add a client to the client list
 */
static int add_client(int fd)
{
    if (g_nclients >= MAX_CLIENTS) {
        return -1;
    }

    g_clients[g_nclients].fd = fd;
    g_clients[g_nclients].auth_done = 1;  /* No auth required by default */
    g_nclients++;

    return 0;
}

/*
 * Remove a client from the client list
 */
static void remove_client(int fd)
{
    int i;

    for (i = 0; i < g_nclients; i++) {
        if (g_clients[i].fd == fd) {
            /* Close the socket */
            tcp_close(fd);

            /* Shift remaining clients */
            for (; i < g_nclients - 1; i++) {
                g_clients[i] = g_clients[i + 1];
            }
            g_nclients--;
            return;
        }
    }
}

/*
 * Handle a client request
 */
static int handle_client_request(ClientInfo *client)
{
    uint8_t msg_buf[P9_MAX_MSG];
    uint8_t resp_buf[P9_MAX_MSG];
    int msg_len;
    size_t resp_len;
    int result;

    /* Set current client fd for FID operations */
    p9_set_client_fd(client->fd);

    /* Receive message */
    msg_len = tcp_recv_msg(client->fd, msg_buf, sizeof(msg_buf));
    if (msg_len < 0) {
        /* Error or disconnect */
        return -1;
    }
    if (msg_len == 0) {
        /* No data available */
        return 0;
    }

    /* Dispatch message */
    resp_len = dispatch_9p(msg_buf, (size_t)msg_len, resp_buf);
    if (resp_len == 0) {
        /* Error during dispatch */
        return -1;
    }

    /* Send response */
    result = tcp_send_msg(client->fd, resp_buf, resp_len);
    if (result < 0) {
        /* Send failed */
        return -1;
    }

    return 0;
}

/*
 * Accept a new connection
 */
static int accept_connection(void)
{
    int client_fd;

    client_fd = tcp_accept(g_listen_fd);
    if (client_fd < 0) {
        return -1;
    }

    /* Ensure socket is in blocking mode */
    {
        int flags = fcntl(client_fd, F_GETFL, 0);
        if (flags >= 0 && (flags & O_NONBLOCK)) {
            fcntl(client_fd, F_SETFL, flags & ~O_NONBLOCK);
        }
    }

    /* Add client */
    if (add_client(client_fd) < 0) {
        tcp_close(client_fd);
        return -1;
    }

    return 0;
}

/*
 * Start the TCP server
 */
int marrow_server_start(MarrowInstance *instance)
{
    if (instance == NULL) {
        return -1;
    }

    if (instance->running) {
        /* Already running */
        return 0;
    }

    /* Start listening */
    g_listen_fd = tcp_listen(instance->config.port);
    if (g_listen_fd < 0) {
        if (instance->config.log_callback) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Failed to listen on port %d",
                     instance->config.port);
            instance->config.log_callback(msg, MARROW_LOG_ERROR);
        }
        return -1;
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Mark as running */
    g_running = 1;
    instance->running = 1;
    instance->listen_fd = g_listen_fd;

    if (instance->config.log_callback) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Server listening on port %d",
                 instance->config.port);
        instance->config.log_callback(msg, MARROW_LOG_INFO);
    }

    return 0;
}

/*
 * Stop the TCP server
 */
void marrow_server_stop(MarrowInstance *instance)
{
    int i;

    if (instance == NULL || !instance->running) {
        return;
    }

    g_running = 0;
    instance->running = 0;

    /* Close all client connections */
    for (i = 0; i < g_nclients; i++) {
        tcp_close(g_clients[i].fd);
    }
    g_nclients = 0;

    /* Close listen socket */
    if (g_listen_fd >= 0) {
        tcp_close(g_listen_fd);
        g_listen_fd = -1;
    }
    instance->listen_fd = -1;

    if (instance->config.log_callback) {
        instance->config.log_callback("Server stopped", MARROW_LOG_INFO);
    }
}

/*
 * Process pending events (non-blocking)
 */
void marrow_server_process_events(MarrowInstance *instance)
{
    fd_set readfds;
    struct timeval tv;
    int max_fd;
    int i;
    int select_result;

    if (instance == NULL || !instance->running) {
        return;
    }

    FD_ZERO(&readfds);
    FD_SET(g_listen_fd, &readfds);
    max_fd = g_listen_fd;

    /* Add all clients to fd_set */
    for (i = 0; i < g_nclients; i++) {
        FD_SET(g_clients[i].fd, &readfds);
        if (g_clients[i].fd > max_fd) {
            max_fd = g_clients[i].fd;
        }
    }

    /* Select with zero timeout (non-blocking) */
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    select_result = select(max_fd + 1, &readfds, NULL, NULL, &tv);
    if (select_result <= 0) {
        /* No events or error */
        return;
    }

    /* Check for new connections */
    if (FD_ISSET(g_listen_fd, &readfds)) {
        accept_connection();
    }

    /* Handle client requests */
    for (i = g_nclients - 1; i >= 0; i--) {
        if (FD_ISSET(g_clients[i].fd, &readfds)) {
            int result = handle_client_request(&g_clients[i]);
            if (result < 0) {
                /* Client disconnected */
                int fd = g_clients[i].fd;
                remove_client(fd);
            }
        }
    }
}

/*
 * Run the server event loop (blocking)
 */
void marrow_server_run(MarrowInstance *instance)
{
    fd_set readfds;
    struct timeval tv;
    int max_fd;
    int i;
    int select_result;

    if (instance == NULL || !instance->running) {
        return;
    }

    if (instance->config.log_callback) {
        instance->config.log_callback("Event loop started", MARROW_LOG_INFO);
    }

    while (g_running && instance->running) {
        FD_ZERO(&readfds);
        FD_SET(g_listen_fd, &readfds);
        max_fd = g_listen_fd;

        /* Add all clients to fd_set */
        for (i = 0; i < g_nclients; i++) {
            FD_SET(g_clients[i].fd, &readfds);
            if (g_clients[i].fd > max_fd) {
                max_fd = g_clients[i].fd;
            }
        }

        /* Select with 100ms timeout */
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        select_result = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (select_result < 0) {
            if (g_running && instance->running) {
                if (instance->config.log_callback) {
                    instance->config.log_callback("select error", MARROW_LOG_ERROR);
                }
            }
            break;
        }

        /* Check for new connections */
        if (FD_ISSET(g_listen_fd, &readfds)) {
            accept_connection();
        }

        /* Handle client requests */
        for (i = g_nclients - 1; i >= 0; i--) {
            if (FD_ISSET(g_clients[i].fd, &readfds)) {
                int result = handle_client_request(&g_clients[i]);
                if (result < 0) {
                    /* Client disconnected */
                    int fd = g_clients[i].fd;
                    remove_client(fd);
                }
            }
        }
    }

    if (instance->config.log_callback) {
        instance->config.log_callback("Event loop stopped", MARROW_LOG_INFO);
    }
}
