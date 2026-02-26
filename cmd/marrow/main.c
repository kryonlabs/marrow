/*
 * Marrow Server - Main Entry Point
 * C89/C90 compliant
 *
 * This is the portable distributed kernel.
 * Graphics/UI services are provided by connecting services (e.g., kryon).
 */

#include "lib9p.h"
#include "libregistry.h"
#include "graphics.h"
#include "../include/auth_dp9ik.h"
#include "../include/auth_p9any.h"
#include "../include/devfactotum.h"
#include "../include/secstore.h"
#include "../lib/platform/socket.h"
#include "rcpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>
#include <time.h>

/*
 * Device initialization functions (external)
 */
extern int devcons_init(P9Node *dev_dir);
extern int devfd_init(P9Node *dev_dir);
extern int devproc_init(P9Node *root);
extern int devenv_init(P9Node *root);
extern int devscreen_init(P9Node *dev_dir, Memimage *screen);
extern int devmouse_init(P9Node *dev_dir);
extern int devkbd_init(P9Node *dev_dir);
extern int devdraw_new_init(P9Node *draw_dir);
extern int drawconn_init(Memimage *screen);
extern void drawconn_cleanup(void);
extern void devscreen_cleanup(void);
extern int svc_init(P9Node *root);

/*
 * Authentication initialization functions (external)
 */
extern int factotum_init(void *root_dir);
extern int secstore_init(void *root_dir);
extern int auth_session_init(void);
extern void auth_session_cleanup(void);
extern int factotum_load_keys(const char *path);
extern int p9any_handler(int client_fd, const char *domain);
extern int secstore_handler(int client_fd);
extern int handle_rcpu_connection(int fd);

/*
 * CPU server initialization (external)
 */
#ifdef INCLUDE_CPU_SERVER
extern int cpu_server_init(P9Node *root);
extern void p9_set_client_fd(int fd);
#endif

/*
 * Namespace manager initialization (external)
 */
#ifdef INCLUDE_NAMESPACE
extern int namespace_init(void);
#endif

/*
 * Client tracking for multi-client support
 */
#define MAX_CLIENTS 16

typedef struct {
    int fd;
    uint32_t client_id;
    time_t connect_time;
    int is_display_client;
} ClientInfo;

static ClientInfo g_clients[MAX_CLIENTS];
static int g_nclients = 0;
static uint32_t g_next_client_id = 1;

/*
 * Signal handler for graceful shutdown
 */
static volatile int running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

/*
 * Protocol detection for rcpu vs 9P
 */
#define PROTOCOL_9P 0
#define PROTOCOL_RCPU 1
#define PROTOCOL_AUTH_P9 2   /* p9 auth */
#define PROTOCOL_AUTH_SEC 3  /* secstore auth */

static int detect_client_protocol(int fd)
{
    char peek[16];
    ssize_t n;
    int i;

    /* Peek at first bytes to determine protocol */
    n = recv(fd, peek, sizeof(peek), MSG_PEEK);
    if (n < 0) {
        fprintf(stderr, "Protocol detection: recv failed: %s\n", strerror(errno));
        return PROTOCOL_9P;
    }
    fprintf(stderr, "Protocol detection: peeked %zd bytes: ", n);
    for (i = 0; i < n && i < 12; i++) {
        if (peek[i] >= 32 && peek[i] <= 126) {
            fprintf(stderr, "%c", peek[i]);
        } else {
            fprintf(stderr, "\\x%02x", (unsigned char)peek[i]);
        }
    }
    fprintf(stderr, "\n");

    /* Check for authentication protocols first - they can start with just 3 bytes */
    if (n >= 3) {
        /* p9 auth negotiation: starts with "p9 " */
        if (memcmp(peek, "p9 ", 3) == 0) {
            fprintf(stderr, "Protocol detection: p9 auth\n");
            return PROTOCOL_AUTH_P9;
        }
    }

    /* Check for rcpu protocol: "NNNNNN\n" (7-digit length + newline) */
    if (n >= 8) {
        int is_digits = 1;
        for (i = 0; i < 7; i++) {
            if (peek[i] < '0' || peek[i] > '9') {
                is_digits = 0;
                break;
            }
        }

        if (is_digits && peek[7] == '\n') {
            fprintf(stderr, "Protocol detection: rcpu (script-based)\n");
            return PROTOCOL_RCPU;
        }
    }

    /* Check for secstore auth (requires at least 10 bytes) */
    if (n >= 10) {
        /* secstore auth: starts with 0x80 0x17 followed by "secstore" */
        if (peek[0] == (char)0x80 && peek[1] == (char)0x17 &&
            memcmp(peek + 2, "secstore", 8) == 0) {
            fprintf(stderr, "Protocol detection: secstore auth\n");
            return PROTOCOL_AUTH_SEC;
        }
    }

    if (n < 8) {
        fprintf(stderr, "Protocol detection: too few bytes, assuming 9P\n");
        return PROTOCOL_9P;
    }

    fprintf(stderr, "Protocol detection: 9P\n");
    return PROTOCOL_9P;
}

/*
 * Drain socket before closing to prevent garbage data issues
 */
static void drain_socket(int fd)
{
    char drain_buf[1024];
    ssize_t n;
    int total_drained = 0;

    fprintf(stderr, "drain_socket: draining fd=%d\n", fd);

    do {
        n = recv(fd, drain_buf, sizeof(drain_buf), MSG_DONTWAIT);
        if (n > 0) {
            total_drained += n;
            fprintf(stderr, "drain_socket: drained %zd bytes (total=%d)\n", n, total_drained);
        }
    } while (n > 0);

    if (total_drained > 0) {
        fprintf(stderr, "drain_socket: total drained: %d bytes\n", total_drained);
    }
}

/*
 * Add client to tracking
 */
static int add_client(int fd)
{
    if (g_nclients >= MAX_CLIENTS) {
        return -1;
    }

    g_clients[g_nclients].fd = fd;
    g_clients[g_nclients].client_id = g_next_client_id++;
    g_clients[g_nclients].connect_time = time(NULL);
    g_clients[g_nclients].is_display_client = 0;
    g_nclients++;

    fprintf(stderr, "Client %u connected (fd=%d, total=%d)\n",
            g_clients[g_nclients - 1].client_id, fd, g_nclients);
    fflush(stderr);

    return 0;
}

/*
 * Remove client from tracking
 */
static void remove_client(int fd)
{
    int i;
    extern void fid_cleanup_conn(int client_fd); /* Declare external function */
    extern int service_unmount_by_client(int client_fd); /* From libregistry */
    extern int service_unregister_by_client(int client_fd); /* From libregistry */

    for (i = 0; i < g_nclients; i++) {
        if (g_clients[i].fd == fd) {
            fprintf(stderr, "Client %u disconnected (fd=%d)\n",
                    g_clients[i].client_id, fd);
            fflush(stderr);

            /* Unregister any services owned by this client */
            service_unregister_by_client(fd);

            /* Unmount any service mounts from this client */
            service_unmount_by_client(fd);

            /* KEY FIX: Wipe FIDs owned by this specific FD */
            fid_cleanup_conn(fd);

            tcp_close(fd);

            /* Move last entry into this slot */
            if (i < g_nclients - 1) {
                g_clients[i] = g_clients[g_nclients - 1];
            }
            g_nclients--;
            return;
        }
    }
}

/*
 * Handle a single client request (non-blocking)
 */
static int handle_client_request(ClientInfo *client)
{
    uint8_t msg_buf[P9_MAX_MSG];
    uint8_t resp_buf[P9_MAX_MSG];
    int msg_len;
    size_t resp_len;
    int result;

    /* Set current client fd for CPU server tracking */
#ifdef INCLUDE_CPU_SERVER
    extern void p9_set_client_fd(int fd);
    p9_set_client_fd(client->fd);
#endif

    /* Receive message (non-blocking) */
    msg_len = tcp_recv_msg(client->fd, msg_buf, sizeof(msg_buf));
    if (msg_len < 0) {
        /* Error or disconnect */
        return -1;
    }
    if (msg_len == 0) {
        /* No data available */
        return 0;
    }

    /* Log received message */
    if (msg_len >= 5) {
        fprintf(stderr, "Client %u: received message len=%d type=0x%02x ",
                client->client_id, msg_len, msg_buf[4]);
        /* Show message type name */
        switch (msg_buf[4]) {
            case 0x64: fprintf(stderr, "(Tversion)\n"); break;
            case 0x65: fprintf(stderr, "(Tauth)\n"); break;
            case 0x66: fprintf(stderr, "(Tattach)\n"); break;
            case 0x6A: fprintf(stderr, "(Twalk)\n"); break;
            case 0x6E: fprintf(stderr, "(Topen)\n"); break;
            case 0x70: fprintf(stderr, "(Tread)\n"); break;
            case 0x72: fprintf(stderr, "(Twrite)\n"); break;
            case 0x73: fprintf(stderr, "(Tclunk)\n"); break;
            default: fprintf(stderr, "(unknown)\n"); break;
        }
    } else {
        fprintf(stderr, "Client %u: received short message len=%d\n",
                client->client_id, msg_len);
    }

    /* Dispatch message */
    resp_len = dispatch_9p(msg_buf, (size_t)msg_len, resp_buf);
    if (resp_len == 0) {
        /* Error */
        fprintf(stderr, "handle_client_request: dispatch_9p returned 0 (error)\n");
        return -1;
    }

    /* Log response message */
    if (resp_len >= 5) {
        fprintf(stderr, "Client %u: sending response len=%zu type=0x%02x ",
                client->client_id, resp_len, resp_buf[4]);
        /* Show response type name */
        switch (resp_buf[4]) {
            case 0x64: fprintf(stderr, "(Rversion)\n"); break;
            case 0x65: fprintf(stderr, "(Rauth)\n"); break;
            case 0x66: fprintf(stderr, "(Rattach)\n"); break;
            case 0x6A: fprintf(stderr, "(Rwalk)\n"); break;
            case 0x6E: fprintf(stderr, "(Ropen)\n"); break;
            case 0x70: fprintf(stderr, "(Rread)\n"); break;
            case 0x72: fprintf(stderr, "(Rwrite)\n"); break;
            case 0x73: fprintf(stderr, "(Rclunk)\n"); break;
            default: fprintf(stderr, "(unknown)\n"); break;
        }
    }

    /* Send response */
    result = tcp_send_msg(client->fd, resp_buf, resp_len);
    if (result < 0) {
        fprintf(stderr, "handle_client_request: tcp_send_msg failed\n");
        return -1;
    }

    return 1;  /* Handled a message */
}

/*
 * Create static file (read-only)
 */
typedef struct {
    const char *content;
} StaticFileData;

static ssize_t static_file_read(char *buf, size_t count, uint64_t offset, void *vdata)
{
    StaticFileData *data = (StaticFileData *)vdata;
    const char *content;
    size_t len;

    if (data == NULL || data->content == NULL) {
        return 0;
    }

    content = data->content;
    len = strlen(content);

    if (offset >= len) {
        return 0;
    }
    if (offset + count > len) {
        count = len - offset;
    }

    memcpy(buf, content + offset, count);
    return count;
}

/*
 * Print usage
 */
static void print_usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --port PORT    TCP port to listen on (default: 17010)\n");
    fprintf(stderr, "  --help         Show this help message\n");
    fprintf(stderr, "\n");
}

/*
 * Parse command line arguments
 */
static int parse_args(int argc, char **argv, int *port)
{
    int i;

    *port = 17010;  /* Default port - standard Plan 9 CPU server port */

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --port requires an argument\n");
                return -1;
            }
            *port = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 1;
        } else {
            fprintf(stderr, "Error: unknown option '%s'\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

/*
 * Main entry point
 */
int main(int argc, char **argv)
{
    int port;
    int listen_fd;
    int client_fd;
    int result;
    P9Node *root = NULL;
    P9Node *dev_dir;
    P9Node *file;
    StaticFileData *static_data;

    /* Parse arguments */
    result = parse_args(argc, argv, &port);
    if (result < 0) {
        return 1;
    }
    if (result > 0) {
        return 0;
    }

    /* Initialize subsystems */
    fprintf(stderr, "Marrow - Portable Distributed Kernel\n");
    fprintf(stderr, "Initializing...\n");

    if (tree_init() < 0) {
        fprintf(stderr, "Error: failed to initialize file tree\n");
        return 1;
    }

    if (fid_init() < 0) {
        fprintf(stderr, "Error: failed to initialize FID table\n");
        return 1;
    }

    /* Initialize authentication subsystem */
    if (auth_session_init() < 0) {
        fprintf(stderr, "Warning: failed to initialize auth sessions\n");
    }

    if (factotum_init(root) < 0) {
        fprintf(stderr, "Warning: failed to initialize factotum\n");
    }

    if (secstore_init(root) < 0) {
        fprintf(stderr, "Warning: failed to initialize secstore\n");
    }

    /* Load default keys */
    if (factotum_load_keys("/etc/marrow/keys") < 0) {
        fprintf(stderr, "No keys loaded, creating default test user\n");
        /* Create default test user */
        factotum_add_key("key proto=dp9ik dom=localhost user=glenda !password=glenda");
    }

#ifdef INCLUDE_NAMESPACE
    /* Initialize namespace manager */
    if (namespace_init() < 0) {
        fprintf(stderr, "Error: failed to initialize namespace manager\n");
        return 1;
    }
#endif

    /* Get root node */
    root = tree_root();
    if (root == NULL) {
        fprintf(stderr, "Error: failed to get root node\n");
        return 1;
    }

#ifdef INCLUDE_CPU_SERVER
    /* Initialize CPU server */
    if (cpu_server_init(root) < 0) {
        fprintf(stderr, "Warning: failed to initialize CPU server\n");
    }
#endif

    /* Initialize service registry */
    if (service_registry_init() < 0) {
        fprintf(stderr, "Warning: failed to initialize service registry\n");
    }

    /* Create /dev directory */
    dev_dir = tree_create_dir(root, "dev");
    if (dev_dir == NULL) {
        fprintf(stderr, "Error: failed to create dev directory\n");
        return 1;
    }

    /* Initialize system devices */
    if (devcons_init(dev_dir) < 0) {
        fprintf(stderr, "Warning: failed to initialize /dev/cons\n");
    }

    if (devfd_init(dev_dir) < 0) {
        fprintf(stderr, "Warning: failed to initialize /dev/fd\n");
    }

    if (devproc_init(root) < 0) {
        fprintf(stderr, "Warning: failed to initialize /proc\n");
    }

    if (devenv_init(root) < 0) {
        fprintf(stderr, "Warning: failed to initialize /env\n");
    }

    /* Initialize graphics - create screen buffer */
    Memimage *screen;
    Rectangle screen_rect;

    screen_rect = Rect(0, 0, 800, 600);
    screen = memimage_alloc(screen_rect, RGBA32);
    if (screen == NULL) {
        fprintf(stderr, "Error: failed to allocate screen\n");
        return 1;
    }

    /* Clear screen to white */
    memfillcolor(screen, 0xFFFFFFFF);

    /* Draw a test pattern - red rectangle to show it's working */
    {
        Memimage *rect_img;
        Rectangle rect_rect;
        rect_rect = Rect(100, 100, 300, 200);
        rect_img = memimage_alloc(rect_rect, RGB24);
        if (rect_img != NULL) {
            memfillcolor(rect_img, 0xFF0000);  /* Red */
            memdraw(screen, rect_rect, rect_img, Pt(0, 0), NULL, Pt(0, 0), SoverD);
            free(rect_img);
        }
    }

    /* Draw a blue rectangle (approximation) */
    {
        Memimage *blue_img;
        Rectangle blue_rect;
        blue_rect = Rect(400, 100, 600, 300);
        blue_img = memimage_alloc(blue_rect, RGB24);
        if (blue_img != NULL) {
            memfillcolor(blue_img, 0x0000FF);  /* Blue */
            memdraw(screen, blue_rect, blue_img, Pt(0, 0), NULL, Pt(0, 0), SoverD);
            free(blue_img);
        }
    }

    /* Draw green text area */
    {
        Memimage *green_img;
        Rectangle green_rect;
        green_rect = Rect(100, 400, 700, 500);
        green_img = memimage_alloc(green_rect, RGB24);
        if (green_img != NULL) {
            memfillcolor(green_img, 0x00FF00);  /* Green */
            memdraw(screen, green_rect, green_img, Pt(0, 0), NULL, Pt(0, 0), SoverD);
            free(green_img);
        }
    }

    /* Initialize draw connection system */
    if (drawconn_init(screen) < 0) {
        fprintf(stderr, "Warning: failed to initialize draw connection system\n");
    }

    fprintf(stderr, "  Created %dx%d RGBA32 screen\n",
            Dx(screen_rect), Dy(screen_rect));

    /* Create /dev/draw directory */
    {
        P9Node *draw_dir;
        draw_dir = tree_create_dir(dev_dir, "draw");
        if (draw_dir == NULL) {
            fprintf(stderr, "Warning: failed to create draw directory\n");
        } else {
            /* Initialize /dev/draw/new */
            if (devdraw_new_init(draw_dir) < 0) {
                fprintf(stderr, "Warning: failed to initialize /dev/draw/new\n");
            }
        }
    }

    /* Initialize graphics devices */
    if (devscreen_init(dev_dir, screen) < 0) {
        fprintf(stderr, "Warning: failed to initialize /dev/screen\n");
    }

    if (devmouse_init(dev_dir) < 0) {
        fprintf(stderr, "Warning: failed to initialize /dev/mouse\n");
    }

    if (devkbd_init(dev_dir) < 0) {
        fprintf(stderr, "Warning: failed to initialize /dev/kbd\n");
    }

    /* Create /mnt directory for service mounting */
    {
        P9Node *mnt_node;
        mnt_node = tree_walk(root, "mnt");
        if (mnt_node == NULL) {
            mnt_node = tree_create_dir(root, "mnt");
            if (mnt_node == NULL) {
                fprintf(stderr, "Error: failed to create /mnt\n");
                return 1;
            }
        }
        fprintf(stderr, "Created /mnt for service mounting\n");
    }

    /* Initialize /svc filesystem for service registry */
    if (svc_init(root) < 0) {
        fprintf(stderr, "Warning: failed to initialize /svc filesystem\n");
    }

    /* Start listening */
    fprintf(stderr, "Listening on 0.0.0.0:%d...\n", port);
    listen_fd = tcp_listen(port);
    if (listen_fd < 0) {
        fprintf(stderr, "Error: failed to listen on port %d\n", port);
        return 1;
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Main loop - select-based I/O multiplexing */
    fprintf(stderr, "Main loop started (multi-client mode)\n");

    while (running) {
        fd_set readfds;
        struct timeval tv;
        int max_fd;
        int i;
        int select_result;

        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);
        max_fd = listen_fd;

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
            if (running) {
                fprintf(stderr, "select error\n");
            }
            break;
        }

        /* Check for new connections */
        if (FD_ISSET(listen_fd, &readfds)) {
            fprintf(stderr, "DEBUG: Connection detected on listen_fd\n");
            fflush(stderr);
            client_fd = tcp_accept(listen_fd);
            fprintf(stderr, "DEBUG: tcp_accept returned fd=%d (errno=%d if error)\n", client_fd, client_fd < 0 ? errno : 0);
            fflush(stderr);
            if (client_fd >= 0) {
                fprintf(stderr, "Accepted connection from client\n");
                fflush(stderr);

                /* Ensure socket is in blocking mode for authentication */
                {
                    int flags = fcntl(client_fd, F_GETFL, 0);
                    if (flags >= 0 && (flags & O_NONBLOCK)) {
                        fprintf(stderr, "Warning: clearing O_NONBLOCK on client socket\n");
                        fcntl(client_fd, F_SETFL, flags & ~O_NONBLOCK);
                    }
                }

                /* Detect protocol */
                int protocol_type;
                fflush(stderr);
                protocol_type = detect_client_protocol(client_fd);

                if (protocol_type == PROTOCOL_RCPU) {
                    fprintf(stderr, "Detected rcpu protocol, spawning shell handler\n");
                    fflush(stderr);
                    /* Handle rcpu connection in separate handler */
                    if (handle_rcpu_connection(client_fd) < 0) {
                        fprintf(stderr, "rcpu handler failed, closing connection\n");
                        fflush(stderr);
                        tcp_close(client_fd);
                    }
                    /* Don't add to select() loop - rcpu manages its own fd */
                } else if (protocol_type == PROTOCOL_AUTH_P9) {
                    fprintf(stderr, "Detected p9 auth, starting authentication\n");
                    fflush(stderr);
                    /* Handle p9any authentication with localhost domain */
                    if (p9any_handler(client_fd, "localhost") < 0) {
                        fprintf(stderr, "p9any authentication failed\n");
                        fflush(stderr);
                        drain_socket(client_fd);
                        tcp_close(client_fd);
                    } else {
                        /* Auth succeeded, add to normal client list */
                        fprintf(stderr, "Authentication successful, adding client\n");
                        if (add_client(client_fd) < 0) {
                            fprintf(stderr, "Too many clients, rejecting connection\n");
                            fflush(stderr);
                            drain_socket(client_fd);
                            tcp_close(client_fd);
                        }
                    }
                } else if (protocol_type == PROTOCOL_AUTH_SEC) {
                    fprintf(stderr, "Detected secstore auth\n");
                    fflush(stderr);
                    /* Handle secstore authentication */
                    if (secstore_handler(client_fd) < 0) {
                        fprintf(stderr, "secstore authentication failed\n");
                        fflush(stderr);
                        drain_socket(client_fd);
                        tcp_close(client_fd);
                    } else {
                        /* Secstore should handle the connection itself */
                        fprintf(stderr, "secstore authentication complete\n");
                    }
                } else {
                    /* Standard 9P client */
                    if (add_client(client_fd) < 0) {
                        fprintf(stderr, "Too many clients, rejecting connection\n");
                        fflush(stderr);
                        tcp_close(client_fd);
                    }
                }
            }
        }

        /* Handle client requests */
        for (i = g_nclients - 1; i >= 0; i--) {
            if (FD_ISSET(g_clients[i].fd, &readfds)) {
                int result = handle_client_request(&g_clients[i]);
                if (result < 0) {
                    /* Client disconnected */
                    remove_client(g_clients[i].fd);
                }
            }
        }
    }

    /* Cleanup */
    fprintf(stderr, "\nShutting down...\n");

    /* Close all client connections */
    {
        int i;
        for (i = 0; i < g_nclients; i++) {
            fid_cleanup_conn(g_clients[i].fd);
            tcp_close(g_clients[i].fd);
        }
    }
    g_nclients = 0;

    /* Cleanup authentication sessions */
    auth_session_cleanup();

    /* Cleanup service registry */
    service_registry_cleanup();

    /* Cleanup device states before tree cleanup */
    drawconn_cleanup();
    devscreen_cleanup();

    tcp_close(listen_fd);

    /* Tree cleanup must happen after device cleanup */
    tree_cleanup();

    fprintf(stderr, "Marrow stopped.\n");

    return 0;
}
