#ifndef LIB9P_H
#define LIB9P_H

/* Include lib9 for 9P protocol types */
#include <lib9.h>
#include <fcall.h>

#include <stddef.h>
#include <stdint.h>

/*
 * C89 compatibility: ssize_t is not defined in C89
 */
#ifdef _WIN32
typedef long ssize_t;
#else
#include <sys/types.h>
#endif

/*
 * 9P Constants (Marrow-specific limits)
 */
#define P9_MAX_VERSION  32
#define P9_MAX_MSG      8192
#define P9_MAX_FID      256
#define P9_MAX_TAG      256
#define P9_MAX_WELEM    16
#define P9_MAX_STR      256

/*
 * Tree node structure
 */
#define P9NODE_DECLARED
typedef struct P9Node {
    char            *name;
    Qid             qid;            /* Use lib9's Qid */
    uint32_t        mode;
    uint32_t        atime;
    uint32_t        mtime;
    uint64_t        length;
    void            *data;
    struct P9Node   *parent;
    struct P9Node   **children;
    int             nchildren;
    int             capacity;
} P9Node;

/*
 * FID structure (Marrow-specific FID tracking)
 */
typedef struct P9Fid {
    uint32_t        fid;            /* FID number */
    int             client_fd;      /* Client socket fd */
    P9Node          *node;          /* Node this FID points to */
    int             is_open;        /* Whether Topen was called */
    uint8_t         mode;           /* Open mode (OREAD, OWRITE, ORDWR) */
    void            *fid_state;     /* FIDState for streaming devices */
} P9Fid;

/*
 * File operation handlers (now include fid_ctx parameter)
 */
typedef ssize_t (*P9ReadFunc)(char *buf, size_t count, uint64_t offset, void *fid_ctx);
typedef ssize_t (*P9WriteFunc)(const char *buf, size_t count, uint64_t offset, void *fid_ctx);

/*
 * Tree management
 */
int tree_init(void);
void tree_cleanup(void);
P9Node *tree_root(void);
P9Node *tree_lookup(P9Node *root, const char *path);
P9Node *tree_walk(P9Node *node, const char *name);
P9Node *tree_create_dir(P9Node *parent, const char *name);
P9Node *tree_create_file(P9Node *parent, const char *name, void *data,
                         ssize_t (*read)(char *, size_t, uint64_t, void *),
                         ssize_t (*write)(const char *, size_t, uint64_t, void *));
int tree_add_child(P9Node *parent, P9Node *child);
int tree_remove_node(P9Node *node);

/*
 * Node operations (UPDATED: now include fid_ctx parameter)
 */
ssize_t node_read(P9Node *node, char *buf, size_t count, uint64_t offset, void *fid_ctx);
ssize_t node_write(P9Node *node, const char *buf, size_t count, uint64_t offset, void *fid_ctx);

/*
 * FID management
 */
int fid_init(void);
void fid_cleanup_conn(int client_fd);
P9Fid *fid_new(uint32_t fid_num, P9Node *node);
P9Fid *fid_get(uint32_t fid_num);
int fid_put(uint32_t fid_num);
int fid_clunk(uint32_t fid_num);

/*
 * Client FID tracking for multi-client support
 */
void p9_set_client_fd(int fd);
int p9_get_client_fd(void);

/*
 * 9P Operation handlers (updated to use lib9)
 */
int handle_tversion(int client_fd, const Fcall *f);
int handle_tauth(int client_fd, const Fcall *f);
int handle_tattach(int client_fd, const Fcall *f);
int handle_twalk(int client_fd, const Fcall *f);
int handle_topen(int client_fd, const Fcall *f);
int handle_tread(int client_fd, const Fcall *f);
int handle_twrite(int client_fd, const Fcall *f);
int handle_tclunk(int client_fd, const Fcall *f);
int handle_tremove(int client_fd, const Fcall *f);
int handle_tstat(int client_fd, const Fcall *f);

/*
 * Main dispatcher
 */
size_t dispatch_9p(const uint8_t *in_buf, size_t in_len, uint8_t *out_buf);

/*
 * Include graphics header for DrawConnection and related types
 */
#include "graphics.h"

/*
 * /dev/draw/new implementation
 */
int devdraw_new_init(P9Node *draw_dir);
ssize_t devdraw_new_read(char *buf, size_t count, uint64_t offset, void *data);

/*
 * /dev/draw/[n]/directory creation
 */
P9Node *drawconn_create_dir(int conn_id);

/*
 * /dev/draw/[n]/data implementation
 */
ssize_t devdraw_data_read(char *buf, size_t count, uint64_t offset, void *data);
ssize_t devdraw_data_write(const char *buf, size_t count, uint64_t offset, void *data);

/*
 * /dev/draw/[n]/ctl implementation
 */
ssize_t devdraw_ctl_read(char *buf, size_t count, uint64_t offset, void *data);
ssize_t devdraw_ctl_write(const char *buf, size_t count, uint64_t offset, void *data);

/*
 * /dev/draw/[n]/refresh implementation
 */
ssize_t devdraw_refresh_read(char *buf, size_t count, uint64_t offset, void *data);

/*
 * Plan 9 graphics protocol processing
 */
int process_draw_messages(DrawConnection *conn, const char *buf, size_t count,
                          char *response, int *resp_len);

/*
 * /dev/audio implementation (9front compatible)
 */
int devaudio_init(P9Node *dev_dir);
ssize_t devaudio_read(char *buf, size_t count, uint64_t offset, void *fid_ctx);
ssize_t devaudio_write(const char *buf, size_t count, uint64_t offset, void *fid_ctx);
ssize_t devaudioctl_read(char *buf, size_t count, uint64_t offset, void *fid_ctx);
ssize_t devaudioctl_write(const char *buf, size_t count, uint64_t offset, void *fid_ctx);

/*
 * Helper functions for handlers
 */
void handlers_set_msize(uint32_t msize);
uint32_t handlers_get_msize(void);
int is_streaming_device(P9Node *node);
int node_get_path(P9Node *node, char *path, size_t path_len);

#endif /* LIB9P_H */
