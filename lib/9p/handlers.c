/*
 * 9P Operation Handlers - Updated to use lib9
 */

#include "lib9p.h"
#include "fid_state.h"
#include "devmouse.h"
#include "devkbd.h"
#include <lib9.h>
#include <fcall.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/*
 * Write all bytes to a file descriptor, handling partial writes.
 * Returns the number of bytes written on success, or -1 on error.
 */
static ssize_t write_all(int fd, const void *buf, size_t count)
{
    ssize_t total_written = 0;
    const uint8_t *p = buf;

    while (total_written < count) {
        ssize_t n = write(fd, p + total_written, count - total_written);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "write_all: write failed: %s\n", strerror(errno));
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "write_all: unexpected EOF\n");
            return -1;
        }
        total_written += n;
    }
    return total_written;
}

/* Ensure 9P constants are available */
#ifndef OREAD
#define OREAD 0
#endif
#ifndef OWRITE
#define OWRITE 1
#endif
#ifndef ORDWR
#define ORDWR 2
#endif
#ifndef OEXEC
#define OEXEC 3
#endif

/*
 * External declarations from ops.c (FID management)
 */
extern int p9_get_client_fd(void);
extern P9Fid *fid_get(uint32_t fid_num);
extern P9Node *tree_root(void);
extern int tree_remove_node(P9Node *node);
extern int tree_add_child(P9Node *parent, P9Node *child);
extern ssize_t node_read(P9Node *node, char *buf, size_t count, uint64_t offset, void *fid_ctx);
extern ssize_t node_write(P9Node *node, const char *buf, size_t count, uint64_t offset, void *fid_ctx);
extern int node_get_path(P9Node *node, char *path, size_t path_len);
extern int is_streaming_device(P9Node *node);

/*
 * External function for draw connections
 */
extern P9Node *drawconn_create_dir(int conn_id);

/*
 * CPU server integration
 */
#ifdef INCLUDE_CPU_SERVER
extern int cpu_server_init(P9Node *root);
extern int cpu_handle_new_client(int client_fd, const char *user, const char *aname);
extern const char *cpu_find_plan9_path(void);
#endif

/*
 * Maximum message size (negotiated)
 */
static uint32_t negotiated_msize = P9_MAX_MSG;

/*
 * Set negotiated message size
 */
void handlers_set_msize(uint32_t msize)
{
    negotiated_msize = msize;
}

/*
 * Get negotiated message size
 */
uint32_t handlers_get_msize(void)
{
    return negotiated_msize;
}

/*
 * Handle Tversion
 */
int handle_tversion(int client_fd, const Fcall *f)
{
    Fcall r;
    uint8_t outbuf[P9_MAX_MSG];
    uint outlen;
    uint32_t final_msize;

    /* Validate message type */
    if (f->type != Tversion) {
        return -1;
    }

    /* We only support 9P2000 */
    if (f->version == NULL || strcmp(f->version, "9P2000") != 0) {
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "unsupported version";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    /* Negotiate message size */
    final_msize = f->msize;
    if (final_msize > P9_MAX_MSG) {
        final_msize = P9_MAX_MSG;
    }
    if (final_msize < 256) {
        final_msize = 256;
    }

    negotiated_msize = final_msize;

    /* Build response using lib9 */
    memset(&r, 0, sizeof(r));
    r.type = Rversion;
    r.tag = f->tag;
    r.msize = final_msize;
    r.version = "9P2000";

    outlen = convS2M(&r, outbuf, sizeof(outbuf));
    if (outlen == 0) {
        return -1;
    }

    return write_all(client_fd, outbuf, outlen);
}

/*
 * Handle Tattach
 */
int handle_tattach(int client_fd, const Fcall *f)
{
    Fcall r;
    uint8_t outbuf[P9_MAX_MSG];
    uint outlen;
    P9Fid *fid_obj;
    P9Node *root;
    int is_cpu_attach;

    fprintf(stderr, "handle_tattach: client_fd=%d, fid=%u, uname=%s, aname=%s\n",
            client_fd, f->fid, f->uname ? f->uname : "(null)",
            f->aname ? f->aname : "(null)");

    /* Validate message type */
    if (f->type != Tattach) {
        return -1;
    }

    /* Check if this is a CPU server attach */
    is_cpu_attach = (f->aname != NULL && strcmp(f->aname, "cpu") == 0);

#ifdef INCLUDE_CPU_SERVER
    if (is_cpu_attach && client_fd >= 0) {
        /* Initialize CPU server session */
        int session_id = cpu_handle_new_client(client_fd, f->uname, f->aname);
        if (session_id < 0) {
            fprintf(stderr, "handle_tattach: failed to create CPU session\n");
            /* Send Rerror */
            memset(&r, 0, sizeof(r));
            r.type = Rerror;
            r.tag = f->tag;
            r.ename = "CPU session failed";
            outlen = convS2M(&r, outbuf, sizeof(outbuf));
            if (outlen == 0) return -1;
            write_all(client_fd, outbuf, outlen);
            return outlen;
        }
    }
#else
    (void)is_cpu_attach;  /* Suppress unused warning when INCLUDE_CPU_SERVER is not defined */
#endif

    /* Get root node */
    root = tree_root();
    if (root == NULL) {
        /* Build Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "no root";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        write_all(client_fd, outbuf, outlen);
        return outlen;
    }

    /* Create FID */
    fid_obj = fid_new(f->fid, root);
    if (fid_obj == NULL) {
        fprintf(stderr, "handle_tattach: FID %u already in use!\n", f->fid);
        /* Build Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "fid in use";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        write_all(client_fd, outbuf, outlen);
        return outlen;
    }

    /* Build response using lib9 */
    memset(&r, 0, sizeof(r));
    r.type = Rattach;
    r.tag = f->tag;
    r.qid = root->qid;

    outlen = convS2M(&r, outbuf, sizeof(outbuf));
    if (outlen == 0) {
        fprintf(stderr, "handle_tattach: convS2M failed\n");
        return -1;
    }

    fprintf(stderr, "handle_tattach: sending Rattach response, outlen=%u\n", outlen);
    ssize_t written = write_all(client_fd, outbuf, outlen);
    fprintf(stderr, "handle_tattach: write_all returned %ld\n", written);
    return written;
}

/*
 * Handle Tauth
 * Return Rerror "no authentication required" - this is the correct 9P way
 * to signal the client should use NOFID as afid in Tattach.
 */
int handle_tauth(int client_fd, const Fcall *f)
{
    Fcall r;
    uint8_t outbuf[P9_MAX_MSG];
    uint outlen;

    /* Validate message type */
    if (f->type != Tauth) {
        return -1;
    }

    /* Send Rerror indicating no authentication required */
    memset(&r, 0, sizeof(r));
    r.type = Rerror;
    r.tag = f->tag;
    r.ename = "no authentication required";

    outlen = convS2M(&r, outbuf, sizeof(outbuf));
    if (outlen == 0) {
        return -1;
    }

    return write_all(client_fd, outbuf, outlen);
}

/*
 * Handle Twalk
 */
int handle_twalk(int client_fd, const Fcall *f)
{
    Fcall r;
    uint8_t outbuf[P9_MAX_MSG];
    uint outlen;
    P9Fid *fid_obj, *newfid_obj;
    P9Node *node, *newnode;
    Qid wqid[P9_MAX_WELEM];
    int i;
    int j;
    int k;
    char temp_name[16];
    int conn_id;
    P9Node *dynamic_node;
    int already_exists;
    int is_numeric;
    int found;
    size_t name_len;

    /* Validate message type */
    if (f->type != Twalk) {
        return -1;
    }

    /* Get source FID */
    fid_obj = fid_get(f->fid);
    if (fid_obj == NULL) {
        fprintf(stderr, "handle_twalk: ERROR - fid_get(%u) returned NULL\n", f->fid);
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "fid not found";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    node = fid_obj->node;

    /* Walk through all path components */
    newnode = node;
    for (i = 0; i < f->nwname; i++) {
        char *wname = f->wname[i];
        name_len = strlen(wname);
        found = 0;

        /* "." means current directory */
        if (name_len == 1 && wname[0] == '.') {
            /* newnode stays the same */
            found = 1;
        }
        /* ".." means parent directory */
        else if (name_len == 2 && wname[0] == '.' && wname[1] == '.') {
            if (newnode->parent != NULL) {
                newnode = newnode->parent;
                found = 1;
            }
        }
        /* Check for dynamic /dev/draw/[n] directories */
        else if (newnode->name != NULL && strcmp(newnode->name, "draw") == 0) {
            /* Check if name is all digits */
            is_numeric = 1;
            for (j = 0; j < name_len && j < 16; j++) {
                if (wname[j] < '0' || wname[j] > '9') {
                    is_numeric = 0;
                    break;
                }
            }
            if (is_numeric && name_len > 0 && name_len < 16) {
                memcpy(temp_name, wname, name_len);
                temp_name[name_len] = '\0';
                conn_id = atoi(temp_name);
                dynamic_node = drawconn_create_dir(conn_id);
                if (dynamic_node != NULL) {
                    /* Add to children if not already present */
                    already_exists = 0;
                    for (k = 0; k < newnode->nchildren; k++) {
                        if (newnode->children[k] != NULL &&
                            strlen(newnode->children[k]->name) == name_len &&
                            memcmp(newnode->children[k]->name, wname, name_len) == 0) {
                            already_exists = 1;
                            newnode = newnode->children[k];
                            break;
                        }
                    }
                    if (!already_exists) {
                        tree_add_child(newnode, dynamic_node);
                        newnode = dynamic_node;
                    }
                    found = 1;
                }
            }
        }

        /* Search children using length-based comparison */
        if (!found && newnode->children != NULL) {
            int j;
            for (j = 0; j < newnode->nchildren; j++) {
                if (newnode->children[j] != NULL) {
                    size_t child_len = strlen(newnode->children[j]->name);
                    if (child_len == name_len &&
                        memcmp(newnode->children[j]->name, wname, name_len) == 0) {
                        newnode = newnode->children[j];
                        found = 1;
                        break;
                    }
                }
            }
        }

        if (!found) {
            /* Send Rerror */
            memset(&r, 0, sizeof(r));
            r.type = Rerror;
            r.tag = f->tag;
            r.ename = "file not found";
            outlen = convS2M(&r, outbuf, sizeof(outbuf));
            if (outlen == 0) return -1;
            return write_all(client_fd, outbuf, outlen);
        }
        /* Store QID for this component */
        wqid[i] = newnode->qid;
    }

    /* Create new FID pointing to final node */
    newfid_obj = fid_new(f->newfid, newnode);
    if (newfid_obj == NULL) {
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "newfid in use";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    /* Build response using lib9 */
    memset(&r, 0, sizeof(r));
    r.type = Rwalk;
    r.tag = f->tag;
    r.nwqid = f->nwname;
    memcpy(r.wqid, wqid, sizeof(Qid) * r.nwqid);

    outlen = convS2M(&r, outbuf, sizeof(outbuf));
    if (outlen == 0) {
        return -1;
    }

    return write_all(client_fd, outbuf, outlen);
}

/*
 * Handle Topen
 */
int handle_topen(int client_fd, const Fcall *f)
{
    Fcall r;
    uint8_t outbuf[P9_MAX_MSG];
    uint outlen;
    P9Fid *fid_obj;
    P9Node *node;
    char path[P9_MAX_STR];
    FIDState *fid_state;

    /* Validate message type */
    if (f->type != Topen) {
        return -1;
    }

    /* Get FID */
    fid_obj = fid_get(f->fid);
    if (fid_obj == NULL) {
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "fid not found";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    node = fid_obj->node;

    /* Check permissions */
    if (f->mode == OREAD || f->mode == ORDWR) {
        /* Read OK */
    }
    if (f->mode == OWRITE || f->mode == ORDWR) {
        /* Write OK */
    }

    /* Mark as open */
    fid_obj->is_open = 1;
    fid_obj->mode = f->mode;

    /* Create FID state for streaming devices */
    if (node_get_path(node, path, sizeof(path)) == 0) {
        if (is_streaming_device(node)) {

            fid_state = fid_state_create(f->fid, client_fd, node);
            if (fid_state == NULL) {
                /* Send Rerror */
                memset(&r, 0, sizeof(r));
                r.type = Rerror;
                r.tag = f->tag;
                r.ename = "out of memory";
                outlen = convS2M(&r, outbuf, sizeof(outbuf));
                if (outlen == 0) return -1;
                return write_all(client_fd, outbuf, outlen);
            }

            fid_state_set_stream(fid_state, 1);

            /* Create device-specific state */
            if (strcmp(path, "/dev/mouse") == 0) {
                MouseFIDState *mouse_state = devmouse_create_fid_state();
                if (mouse_state == NULL) {
                    fid_state_destroy(fid_state);
                    memset(&r, 0, sizeof(r));
                    r.type = Rerror;
                    r.tag = f->tag;
                    r.ename = "out of memory";
                    outlen = convS2M(&r, outbuf, sizeof(outbuf));
                    if (outlen == 0) return -1;
                    return write_all(client_fd, outbuf, outlen);
                }
                fid_state_set_device(fid_state, mouse_state,
                                    (void (*)(void*))devmouse_destroy_fid_state);
            } else if (strcmp(path, "/dev/kbd") == 0) {
                KbdFIDState *kbd_state = devkbd_create_fid_state();
                if (kbd_state == NULL) {
                    fid_state_destroy(fid_state);
                    memset(&r, 0, sizeof(r));
                    r.type = Rerror;
                    r.tag = f->tag;
                    r.ename = "out of memory";
                    outlen = convS2M(&r, outbuf, sizeof(outbuf));
                    if (outlen == 0) return -1;
                    return write_all(client_fd, outbuf, outlen);
                }
                fid_state_set_device(fid_state, kbd_state,
                                    (void (*)(void*))devkbd_destroy_fid_state);
            }

            fid_obj->fid_state = fid_state;
        }
    }

    /* Build response using lib9 */
    memset(&r, 0, sizeof(r));
    r.type = Ropen;
    r.tag = f->tag;
    r.qid = node->qid;
    r.iounit = 0; /* No preferred I/O size */

    outlen = convS2M(&r, outbuf, sizeof(outbuf));
    if (outlen == 0) {
        return -1;
    }

    return write_all(client_fd, outbuf, outlen);
}

/*
 * Handle Tread for directories
 * NOTE: This function needs to be reimplemented to use lib9's Dir type
 * and convD2M function. For now, it returns an error.
 */
static int handle_directory_read(int client_fd, P9Fid *fid_obj, const Fcall *f)
{
    Fcall r;
    uint8_t outbuf[P9_MAX_MSG];
    uint outlen;

    /* Directory reading needs to be reimplemented using lib9's Dir type
     * and convD2M function. For now, return an error. */

    memset(&r, 0, sizeof(r));
    r.type = Rerror;
    r.tag = f->tag;
    r.ename = "directory read not yet implemented";
    outlen = convS2M(&r, outbuf, sizeof(outbuf));
    if (outlen == 0) return -1;
    return write_all(client_fd, outbuf, outlen);
}

/*
 * Handle Tread
 */
int handle_tread(int client_fd, const Fcall *f)
{
    Fcall r;
    uint8_t outbuf[P9_MAX_MSG];
    uint outlen;
    P9Fid *fid_obj;
    P9Node *node;
    ssize_t nread;
    char data[P9_MAX_MSG];
    void *fid_ctx;
    uint32_t count;

    /* Validate message type */
    if (f->type != Tread) {
        return -1;
    }

    /* Get FID */
    fid_obj = fid_get(f->fid);
    if (fid_obj == NULL) {
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "fid not found";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    node = fid_obj->node;

    /* Check if directory */
    if (node->qid.type & QTDIR) {
        return handle_directory_read(client_fd, fid_obj, f);
    }

    /* Limit count */
    count = f->count;
    if (count > negotiated_msize - 24) {
        count = negotiated_msize - 24;
    }

    /* Get FID context for device handlers */
    fid_ctx = NULL;
    if (fid_obj->fid_state != NULL) {
        fid_ctx = fid_state_get_device(fid_obj->fid_state);
    }

    /* Read from file - pass FID context */
    nread = node_read(node, data, count, f->offset, fid_ctx);
    if (nread < 0) {
        fprintf(stderr, "handle_tread: read error for node '%s'\n", node->name);
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "read error";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    /* Build response using lib9 */
    memset(&r, 0, sizeof(r));
    r.type = Rread;
    r.tag = f->tag;
    r.count = nread;
    r.data = data;

    outlen = convS2M(&r, outbuf, sizeof(outbuf));
    if (outlen == 0) {
        return -1;
    }

    return write_all(client_fd, outbuf, outlen);
}

/*
 * Handle Twrite
 */
int handle_twrite(int client_fd, const Fcall *f)
{
    Fcall r;
    uint8_t outbuf[P9_MAX_MSG];
    uint outlen;
    P9Fid *fid_obj;
    P9Node *node;
    ssize_t nwritten;

    /* Validate message type */
    if (f->type != Twrite) {
        return -1;
    }

    /* Get FID */
    fid_obj = fid_get(f->fid);
    if (fid_obj == NULL) {
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "fid not found";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    node = fid_obj->node;

    /* Check if directory */
    if (node->qid.type & QTDIR) {
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "is directory";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    /* Write to file - no FID context needed for writes */
    nwritten = node_write(node, (const char*)f->data, f->count, f->offset, NULL);
    if (nwritten < 0) {
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "write error";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    /* Build response using lib9 */
    memset(&r, 0, sizeof(r));
    r.type = Rwrite;
    r.tag = f->tag;
    r.count = nwritten;

    outlen = convS2M(&r, outbuf, sizeof(outbuf));
    if (outlen == 0) {
        return -1;
    }

    return write_all(client_fd, outbuf, outlen);
}

/*
 * Handle Tclunk
 */
int handle_tclunk(int client_fd, const Fcall *f)
{
    Fcall r;
    uint8_t outbuf[P9_MAX_MSG];
    uint outlen;
    int result;

    /* Validate message type */
    if (f->type != Tclunk) {
        return -1;
    }

    /* Clunk FID (will cleanup FID state) */
    result = fid_clunk(f->fid);
    if (result < 0) {
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "fid not found";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    /* Build response using lib9 */
    memset(&r, 0, sizeof(r));
    r.type = Rclunk;
    r.tag = f->tag;

    outlen = convS2M(&r, outbuf, sizeof(outbuf));
    if (outlen == 0) {
        return -1;
    }

    return write_all(client_fd, outbuf, outlen);
}

/*
 * Handle Tstat
 */
int handle_tstat(int client_fd, const Fcall *f)
{
    Fcall r;
    uint8_t outbuf[P9_MAX_MSG];
    uint outlen;
    P9Fid *fid_obj;
    P9Node *node;
    Dir stat;
    static uchar statbuf[P9_MAX_MSG];

    /* Validate message type */
    if (f->type != Tstat) {
        return -1;
    }

    /* Get FID */
    fid_obj = fid_get(f->fid);
    if (fid_obj == NULL) {
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "fid not found";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    node = fid_obj->node;

    /* Build stat structure using lib9's Dir */
    memset(&stat, 0, sizeof(stat));
    stat.type = 0;
    stat.dev = 0;
    stat.qid = node->qid;
    stat.mode = node->mode;
    stat.atime = node->atime;
    stat.mtime = node->mtime;
    stat.length = node->length;
    stat.name = node->name;
    stat.uid = "none";
    stat.gid = "none";
    stat.muid = "none";

    /* Build response using lib9 */
    memset(&r, 0, sizeof(r));
    r.type = Rstat;
    r.tag = f->tag;
    /* Convert Dir to wire format */
    r.nstat = convD2M(&stat, statbuf, sizeof(statbuf));
    r.stat = statbuf;

    outlen = convS2M(&r, outbuf, sizeof(outbuf));
    if (outlen == 0) {
        return -1;
    }

    return write_all(client_fd, outbuf, outlen);
}

/*
 * Handle Tremove
 * Removes a node from the tree and clunks the FID
 */
int handle_tremove(int client_fd, const Fcall *f)
{
    Fcall r;
    uint8_t outbuf[P9_MAX_MSG];
    uint outlen;
    P9Fid *fid_obj;
    P9Node *node;
    int remove_result;

    /* Validate message type */
    if (f->type != Tremove) {
        return -1;
    }

    /* Get FID - return error if fid doesn't exist */
    fid_obj = fid_get(f->fid);
    if (fid_obj == NULL) {
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "fid not found";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    node = fid_obj->node;

    /* Attempt removal from tree */
    remove_result = tree_remove_node(node);

    /* ALWAYS clunk the fid per 9P spec, even if removal fails */
    fid_clunk(f->fid);

    if (remove_result < 0) {
        /* Send Rerror */
        memset(&r, 0, sizeof(r));
        r.type = Rerror;
        r.tag = f->tag;
        r.ename = "permission denied";
        outlen = convS2M(&r, outbuf, sizeof(outbuf));
        if (outlen == 0) return -1;
        return write_all(client_fd, outbuf, outlen);
    }

    /* Build response using lib9 */
    memset(&r, 0, sizeof(r));
    r.type = Rremove;
    r.tag = f->tag;

    outlen = convS2M(&r, outbuf, sizeof(outbuf));
    if (outlen == 0) {
        return -1;
    }

    return write_all(client_fd, outbuf, outlen);
}

/*
 * Main 9P message dispatcher
 */
size_t dispatch_9p(const uint8_t *in_buf, size_t in_len, uint8_t *out_buf)
{
    Fcall f;
    uint parsed;
    int result;
    int client_fd;

    /* Parse message using lib9 */
    parsed = convM2S((uchar*)in_buf, in_len, &f);
    if (parsed == 0) {
        fprintf(stderr, "dispatch_9p: failed to parse message\n");
        return 0;
    }

    /* Get current client fd */
    client_fd = p9_get_client_fd();

    /* Dispatch based on message type */
    switch (f.type) {
        case Tversion:
            result = handle_tversion(client_fd, &f);
            break;

        case Tauth:
            result = handle_tauth(client_fd, &f);
            break;

        case Tattach:
            result = handle_tattach(client_fd, &f);
            break;

        case Twalk:
            result = handle_twalk(client_fd, &f);
            break;

        case Topen:
            result = handle_topen(client_fd, &f);
            break;

        case Tread:
            result = handle_tread(client_fd, &f);
            break;

        case Twrite:
            result = handle_twrite(client_fd, &f);
            break;

        case Tclunk:
            result = handle_tclunk(client_fd, &f);
            break;

        case Tremove:
            result = handle_tremove(client_fd, &f);
            break;

        case Tstat:
            result = handle_tstat(client_fd, &f);
            break;

        default:
            /* Unknown message type - send Rerror */
            {
                Fcall r;
                uint outlen;
                memset(&r, 0, sizeof(r));
                r.type = Rerror;
                r.tag = f.tag;
                r.ename = "not supported";
                outlen = convS2M(&r, out_buf, P9_MAX_MSG);
                if (outlen == 0) return 0;
                result = write_all(client_fd, out_buf, outlen);
            }
            break;
    }

    return (result > 0) ? result : 0;
}
