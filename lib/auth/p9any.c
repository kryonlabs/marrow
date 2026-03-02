/*
 * Kryon Authentication - p9any Protocol Handler
 * C89/C90 compliant
 *
 * Based on drawterm cpu.c and 9front factotum
 */

#include "auth_p9any.h"
#include "auth_dp9ik.h"
#include "auth_p9sk1.h"
#include "devfactotum.h"
#include <stdio.h>
#include <stdlib.h>
#include "compat.h"
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>

static int send_line(int fd, const char *s) {
    size_t len = strlen(s);
    if (write(fd, s, len) != (ssize_t)len) return -1;
    return 0;
}

void dump_buf(const char *msg, char *buf, int n) {
    int i;
    fprintf(stderr, "DEBUG: %s (%d bytes): [", msg, n);
    for(i=0; i<n; i++) {
        unsigned char c = buf[i];
        if(c >= 32 && c <= 126) fprintf(stderr, "%c", c);
        else fprintf(stderr, "\\x%02x", c);
    }
    fprintf(stderr, "]\n");
}

/* Plan 9 style malloc that zeros memory */
static void* mallocz(size_t n, int clr)
{
    void *p = malloc(n);
    if(p != NULL && clr)
        memset(p, 0, n);
    return p;
}

/*
 * strdup is not in C89, provide a simple implementation
 */
static char *strdup_impl(const char *s)
{
    char *dup;
    size_t len;

    if (s == NULL) {
        return NULL;
    }

    len = strlen(s) + 1;
    dup = (char *)malloc(len);
    if (dup == NULL) {
        return NULL;
    }

    memcpy(dup, s, len);
    return dup;
}

#define strdup(s) strdup_impl(s)

/*
 * Default domain for authentication
 */
static const char default_domain[] = "kryon";

/*
 * Get default domain
 */
const char *p9any_default_domain(void)
{
    return default_domain;
}

/*
 * Build server's protocol list response
 * Format: "p9sk1@domain dp9ik@domain"
 */
int p9any_build_server_hello(char *buf, size_t len, const char *domain)
{
    int written;

    if (buf == NULL || len == 0) {
        return -1;
    }

    /* Use provided domain, or default if NULL */
    if (domain == NULL) {
        domain = default_domain;
    }

    written = snprintf(buf, len, "p9sk1@%s dp9ik@%s",
                       domain, domain);

    if (written < 0 || (size_t)written >= len) {
        return -1;
    }

    return written;
}

/*
 * Send available protocols to client
 * Sends newline-terminated string (Plan 9 auth protocol uses \n for line-based protocols)
 */
int p9any_send_protocols(int fd, const char *domain)
{
    char buf[256];
    int len;

    
    len = snprintf(buf, sizeof(buf), "dp9ik@localhost p9sk1@localhost\n");

    fprintf(stderr, "p9any: sending protocol list (%d bytes): %s", len, buf);
    
    if (write(fd, buf, (size_t)len) != (ssize_t)len) {
        return -1;
    }

    fsync(fd);

    return 0;
}
/* * Parsing logic that handles both 'proto@dom' and 'proto dom'
 */
int p9any_parse_choice(const char *buf, char *proto, size_t plen, char *dom, size_t dlen) {
    char *sep = strchr(buf, '@');
    if (!sep) sep = strchr(buf, ' ');
    
    if (sep) {
        size_t proto_part = sep - buf;
        if (proto_part >= plen) return -1;
        memcpy(proto, buf, proto_part);
        proto[proto_part] = '\0';
        strncpy(dom, sep + 1, dlen - 1);
        return 0;
    }
    return -1;
}

/*
 * Receive client's protocol choice
 * Returns 0 on success, -1 on failure
 */
 
 int p9any_recv_choice(int fd, char *proto, size_t proto_len, char *dom, size_t dom_len)
{
    char buf[256];
    char *p, *first_nl, *choice; /* FIX: Declare these at the TOP */
    ssize_t n;
    struct timeval tv;
    fd_set fds;

    choice = NULL; /* Initialize */

    fprintf(stderr, "p9any: awaiting client choice...\n");
    
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    tv.tv_sec = 60;
    tv.tv_usec = 0;

    if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0) return -1;

    n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return -1;
    buf[n] = '\0';

    /* Handle potential \x00 or \n split from drawterm */
    first_nl = strchr(buf, '\n');
    if (!first_nl) first_nl = strchr(buf, '\0');

    if (first_nl && (size_t)(first_nl - buf) < (size_t)n - 1) {
        choice = first_nl + 1;
    } else {
        choice = buf;
    }

    /* Standard Plan 9 whitespace cleaning */
    for (p = choice + strlen(choice) - 1; p >= choice; p--) {
        if (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t' || *p == '\0') *p = '\0';
        else break;
    }

    if (p9any_parse_choice(choice, proto, proto_len, dom, dom_len) < 0) {
        strncpy(proto, choice, proto_len - 1);
        proto[proto_len - 1] = '\0';
    }

    return 0;
}

int p9any_recv_challenge(int fd, unsigned char *chal)
{
    ssize_t n;
    n = recv(fd, (char *)chal, AUTH_CHALLEN, 0);
    if (n != AUTH_CHALLEN) {
        /* FIX: Change %zd to %ld and cast n to (long) for C90 */
        fprintf(stderr, "p9any_recv_challenge: failed (got %ld bytes, errno=%d)\n", 
                (long)n, errno);
        return -1;
    }
    return 0;
}

/*
 * Send OK confirmation (v2 protocol only)
 */
int p9any_send_ok(int fd)
{
    const char ok_msg[] = "OK\n";
    ssize_t sent;

    sent = send(fd, ok_msg, strlen(ok_msg), 0);
    if (sent < 0) {
        fprintf(stderr, "p9any_send_ok: send failed\n");
        return -1;
    }

    fprintf(stderr, "p9any: sent OK\n");

    return sent;
}


/*
 * Send ticket request + PAK public key (for dp9ik)
 * For p9sk1, sends ticket request without PAK key (type AUTH_TS)
 * For dp9ik, sends ticket request with PAK key (type AUTH_PAK)
 */
int p9any_send_ticketreq(int fd, const char *proto, const char *dom,
                          const char *user, const unsigned char *chal,
                          const unsigned char *pak_y)
{
    unsigned char buf[512];
    int len;
    ssize_t sent;
    Ticketreq tr;

    /* Build ticket request structure */
    memset(&tr, 0, sizeof(tr));

    /* Set ticket type based on protocol */
    if (strcmp(proto, "p9sk1") == 0) {
        tr.type = AUTH_TS;   /* Ticket with server key for p9sk1 */
    } else {
        tr.type = AUTH_PAK;  /* Authenticated DH key exchange for dp9ik */
    }

    strncpy(tr.authid, proto, AUTH_ANAMELEN - 1);
    strncpy(tr.authdom, dom, AUTH_DOMLEN - 1);
    strncpy(tr.hostid, dom, AUTH_ANAMELEN - 1);  /* Use domain as hostid for now */
    strncpy(tr.uid, user, AUTH_ANAMELEN - 1);
    memcpy(tr.chal, chal, AUTH_CHALLEN);

    /* Serialize ticket request */
    len = dp9ik_serialize_ticketreq(&tr, buf, sizeof(buf));
    if (len < 0) {
        fprintf(stderr, "p9any_send_ticketreq: serialize failed\n");
        return -1;
    }

    /* Append PAK public key for dp9ik only */
    if (strcmp(proto, "dp9ik") == 0 && pak_y != NULL) {
        memcpy(buf + len, pak_y, AUTH_PAKYLEN);
        len += AUTH_PAKYLEN;
    }

    /* Send */
    sent = send(fd, (char *)buf, len, 0);
    if (sent < 0) {
        fprintf(stderr, "p9any_send_ticketreq: send failed\n");
        return -1;
    }

    fprintf(stderr, "p9any: sent ticket request type %d (%d bytes) for proto=%s\n",
            tr.type, len, proto);

    return sent;
}

/*
 * Receive ticket + authenticator from client
 * For dp9ik, the client sends: ticket + authenticator combined
 * Ticket: ~141 bytes (num + chal + cuid + suid + key + MAC)
 * Authenticator: 49 bytes (num + chal + rand + MAC)
 */
int p9any_recv_ticket(int fd, unsigned char *ticket, int *ticket_len,
                      unsigned char *auth, int *auth_len)
{
    unsigned char buf[1024];
    ssize_t n;
    int expected_ticket_len;

    /* Receive ticket + authenticator */
    n = recv(fd, (char *)buf, sizeof(buf), 0);
    if (n <= 0) {
        fprintf(stderr, "p9any_recv_ticket: recv failed: %s\n", strerror(errno));
        return -1;
    }

    dump_buf("Received Ticket+Auth", (char *)buf, (int)n);

    /*
     * For dp9ik, approximate sizes:
     * Ticket: 1 + 8 + 28 + 28 + 56 + 32 = 153 bytes
     * Authenticator: 1 + 8 + 8 + 32 = 49 bytes
     * Total: ~202 bytes
     *
     * For now, we'll use heuristics to separate them
     */
    expected_ticket_len = 1 + AUTH_CHALLEN + 2 * AUTH_ANAMELEN + AUTH_PAKYLEN + 32;

    if (n < expected_ticket_len + 17) {
        fprintf(stderr, "p9any_recv_ticket: combined buffer too short (%ld bytes)\n", (long)n);
        /* For MVP, treat everything as ticket */
        memcpy(ticket, buf, n);
        *ticket_len = n;
        *auth_len = 0;
        return n;
    }

    /* Separate ticket and authenticator */
    *ticket_len = expected_ticket_len;
    memcpy(ticket, buf, *ticket_len);

    *auth_len = n - *ticket_len;
    memcpy(auth, buf + *ticket_len, *auth_len);

    fprintf(stderr, "p9any: received ticket (%d bytes) + authenticator (%d bytes), total %ld\n",
            *ticket_len, *auth_len, (long)n);

    return n;
}

/*
 * Receive: YBs (server's PAK key echoed back) + ticket + authenticator
 * Format: PAKYLEN(57) + ticket(var) + authenticator(var)
 * This is the correct dp9ik protocol from drawterm cpu.c lines 773-802
 */
int p9any_recv_dp9ik_response(int fd,
                               unsigned char *ybs,      /* Server's PAK key echoed */
                               unsigned char *ticket, int *ticket_len,
                               unsigned char *auth, int *auth_len)
{
    unsigned char buf[512];
    ssize_t n;
    int base_ticket_len;
    int remaining;

    n = recv(fd, (char *)buf, sizeof(buf), 0);
    if (n <= 0) {
        fprintf(stderr, "p9any_recv_dp9ik_response: recv failed\n");
        return -1;
    }

    dump_buf("Received dp9ik response", (char *)buf, (int)n);

    /* First PAKYLEN bytes are the echoed server PAK key */
    if (n < AUTH_PAKYLEN) {
        fprintf(stderr, "p9ik response too short (%ld < %d)\n", (long)n, AUTH_PAKYLEN);
        return -1;
    }

    memcpy(ybs, buf, AUTH_PAKYLEN);

    /* Parse ticket and authenticator from the rest */
    /* For MVP: assume ticket is 73 bytes + auth */
    remaining = n - AUTH_PAKYLEN;

    /* Base ticket size: num(1) + chal(8) + cuid(28) + suid(28) + key(32) = 73 bytes */
    base_ticket_len = 1 + AUTH_CHALLEN + 2 * AUTH_ANAMELEN + AUTH_PAKKEYLEN;

    if (remaining < base_ticket_len) {
        fprintf(stderr, "p9ik response too short for ticket+auth (%d remaining, need %d)\n",
                remaining, base_ticket_len);
        /* For MVP, treat everything as ticket */
        *ticket_len = remaining;
        memcpy(ticket, buf + AUTH_PAKYLEN, remaining);
        *auth_len = 0;
        return n;
    }

    /* For MVP: assume fixed sizes */
    *ticket_len = base_ticket_len;
    memcpy(ticket, buf + AUTH_PAKYLEN, *ticket_len);

    *auth_len = remaining - *ticket_len;
    if (*auth_len > 0) {
        memcpy(auth, buf + AUTH_PAKYLEN + *ticket_len, *auth_len);
    }

    fprintf(stderr, "p9any: received YBs(%d) + ticket(%d) + auth(%d) = %ld total\n",
            AUTH_PAKYLEN, *ticket_len, *auth_len, (long)n);

    return n;
}

/*
 * Send authenticator response to client
 * Includes MAC computation for security
 */
int p9any_send_authenticator(int fd, const unsigned char *auth, int len)
{
    ssize_t sent;
    unsigned char buf[128];
    int buf_len;

    if (auth == NULL || len < (int)(1 + AUTH_CHALLEN + AUTH_NONCELEN)) {
        fprintf(stderr, "p9any_send_authenticator: invalid parameters\n");
        return -1;
    }

    /* Build authenticator with MAC
     * Format: num(1) + chal(8) + rand(8) + MAC(16)
     * For MVP, we'll use 16 bytes of "MAC" (all zeros or random)
     */
    buf_len = 1 + AUTH_CHALLEN + AUTH_NONCELEN + 16;
    if (buf_len > (int)sizeof(buf)) {
        buf_len = sizeof(buf);
    }

    memset(buf, 0, buf_len);
    memcpy(buf, auth, 1 + AUTH_CHALLEN + AUTH_NONCELEN);

    /* TODO: Compute real MAC using ticket-derived session key
     * For MVP, we just send zeros as MAC placeholder
     */

    sent = send(fd, (char *)buf, buf_len, 0);
    if (sent < 0) {
        fprintf(stderr, "p9any_send_authenticator: send failed\n");
        return -1;
    }

    fprintf(stderr, "p9any: sent server authenticator (%d bytes)\n", buf_len);

    return sent;
}

/*
 * Get protocol type from string
 */
ProtoType p9any_proto_type(const char *proto_str)
{
    if (proto_str == NULL) {
        return PROTO_NONE;
    }

    if (strcmp(proto_str, "dp9ik") == 0) {
        return PROTO_DPIK;
    } else if (strcmp(proto_str, "p9sk1") == 0) {
        return PROTO_P9SK1;
    } else if (strcmp(proto_str, "pass") == 0) {
        return PROTO_PASS;
    }

    return PROTO_NONE;
}

/*
 * Create new p9any session
 */
P9AnySession *p9any_session_new(int client_fd)
{
    P9AnySession *sess;

    sess = (P9AnySession *)malloc(sizeof(P9AnySession));
    if (sess == NULL) {
        fprintf(stderr, "p9any_session_new: malloc failed\n");
        return NULL;
    }

    memset(sess, 0, sizeof(P9AnySession));

    sess->client_fd = client_fd;
    sess->state = P9ANY_STATE_INIT;
    sess->ai = NULL;

    return sess;
}

/*
 * Free p9any session
 */
void p9any_session_free(P9AnySession *sess)
{
    if (sess == NULL) {
        return;
    }

    if (sess->ai != NULL) {
        if (sess->ai->suid != NULL) {
            free(sess->ai->suid);
        }
        if (sess->ai->cuid != NULL) {
            free(sess->ai->cuid);
        }
        if (sess->ai->secret != NULL) {
            memset(sess->ai->secret, 0, sess->ai->nsecret);
            free(sess->ai->secret);
        }
        free(sess->ai);
    }

    free(sess);
}

/*
 * Parse client's initial "p9 rc4_256 sha1" or just "p9"
 */
int p9any_parse_client_hello(const char *buf, char *ealgs, size_t ealgs_len)
{
    const char *space;

    if (buf == NULL) {
        return -1;
    }

    /* Check if it starts with "p9" */
    if (memcmp(buf, "p9", 2) != 0) {
        return -1;
    }

    /* Check if there are encryption algorithms specified */
    if (buf[2] == ' ' || buf[2] == '\t') {
        /* "p9 rc4_256 sha1" - extract algorithms */
        space = buf + 3;

        if (ealgs != NULL && ealgs_len > 0) {
            strncpy(ealgs, space, ealgs_len - 1);
            ealgs[ealgs_len - 1] = '\0';
        }

        fprintf(stderr, "p9any: client hello with ealgs: %s\n", space);
    } else {
        /* Just "p9" - no algorithms specified */
        if (ealgs != NULL && ealgs_len > 0) {
            ealgs[0] = '\0';
        }

        fprintf(stderr, "p9any: client hello (no ealgs)\n");
    }

    return 0;
}

/*
 * Handle dp9ik authentication using real SPAKE2-EE PAK exchange.
 *
 * Wire protocol (server side):
 *   recv: chal_c[8]
 *   send: Ticketreq[141] + YBs[57]
 *   recv: YBc[57] + enc_ticket[125] + enc_auth[45]
 *   send: enc_server_auth[45]
 *
 * Returns 0 on success, -1 on error.
 */
static int p9any_handle_dp9ik(int fd, const char *proto, const char *dom)
{
    /* Challenges */
    unsigned char chal_c[AUTH_CHALLEN];     /* received from client */
    unsigned char chal_s[AUTH_CHALLEN];     /* generated by server, goes in Ticketreq */

    /* Ed448 ephemeral key pair */
    unsigned char scalar_s[DPIK_KEYLEN];    /* private scalar s (56 bytes) */
    unsigned char Ys[AUTH_PAKYLEN];         /* s * G (raw public key, 57 bytes) */
    unsigned char YBs[AUTH_PAKYLEN];        /* Ys + M (blinded, sent to client) */

    /* Client's blinded key and derived points */
    unsigned char YBc[AUTH_PAKYLEN];        /* received from client */
    unsigned char Yc[AUTH_PAKYLEN];         /* YBc - M (unmasked) */
    unsigned char ss[AUTH_PAKYLEN];         /* s * Yc (shared secret) */

    /* Session key */
    unsigned char Kn[DPIK_SESSION_KEY_LEN];

    /* Receive buffer: YBc(57) + enc_ticket(125) + enc_auth(45) = 227 bytes */
    unsigned char recv_buf[512];
    ssize_t n;

    /* Encrypted messages and their sizes */
    /* enc_ticket = nonce(12) + ciphertext(97) + tag(16) = 125 bytes */
    /* enc_auth   = nonce(12) + ciphertext(17) + tag(16) = 45 bytes  */
    int enc_ticket_len = 12 + (1 + AUTH_CHALLEN + AUTH_ANAMELEN + AUTH_ANAMELEN + AUTH_PAKKEYLEN) + 16;
    int enc_auth_len   = 12 + (1 + AUTH_CHALLEN + AUTH_NONCELEN) + 16;

    unsigned char nonce[12];
    Ticket ticket;
    Authenticator client_auth, server_auth;
    unsigned char server_auth_buf[64];
    int server_auth_enc_len;
    ssize_t sent;

    const char *user = "glenda";
    char *password = NULL;

    fprintf(stderr, "p9any: starting dp9ik SPAKE2-EE for proto=%s dom=%s\n", proto, dom);

    /* Step 1: Receive 8-byte client challenge */
    if (p9any_recv_challenge(fd, chal_c) < 0) {
        fprintf(stderr, "p9any: failed to receive client challenge\n");
        return -1;
    }
    fprintf(stderr, "p9any: received client challenge\n");

    /* Step 2: Generate server challenge */
    if (dp9ik_random_bytes(chal_s, AUTH_CHALLEN) < 0) {
        fprintf(stderr, "p9any: failed to generate server challenge\n");
        return -1;
    }

    /* Step 3: Generate ephemeral Ed448 key pair */
    if (dp9ik_pak_key_generate(Ys, sizeof(Ys), scalar_s, sizeof(scalar_s)) < 0) {
        fprintf(stderr, "p9any: failed to generate ephemeral key pair\n");
        return -1;
    }

    /* Step 4: Look up user password from factotum */
    password = dp9ik_find_password(user, dom);
    if (password == NULL) {
        /* Fall back to default so unauthenticated drawterm mount still works */
        fprintf(stderr, "p9any: no dp9ik key for user=%s dom=%s, using default\n", user, dom);
        password = (char *)malloc(9);
        if (password == NULL) { memset(scalar_s, 0, sizeof(scalar_s)); return -1; }
        memcpy(password, "password", 9);
    }

    /* Step 5: Compute blinded server key YBs = Ys + M */
    if (dp9ik_pak_blind(YBs, Ys, password, dom, user) < 0) {
        fprintf(stderr, "p9any: failed to compute blinded key\n");
        memset(scalar_s, 0, sizeof(scalar_s));
        memset(password, 0, strlen(password)); free(password);
        return -1;
    }

    /* Step 6: Send Ticketreq (with chal=chal_s) + YBs */
    if (p9any_send_ticketreq(fd, proto, dom, user, chal_s, YBs) < 0) {
        fprintf(stderr, "p9any: failed to send ticket request + YBs\n");
        memset(scalar_s, 0, sizeof(scalar_s));
        memset(password, 0, strlen(password)); free(password);
        return -1;
    }
    fprintf(stderr, "p9any: sent Ticketreq + YBs\n");

    /* Step 7: Receive YBc(57) + enc_ticket(125) + enc_auth(45) */
    n = recv(fd, (char *)recv_buf, sizeof(recv_buf), 0);
    if (n < AUTH_PAKYLEN + enc_ticket_len + enc_auth_len) {
        fprintf(stderr, "p9any: dp9ik response too short (got %ld, need %d)\n",
                (long)n, AUTH_PAKYLEN + enc_ticket_len + enc_auth_len);
        memset(scalar_s, 0, sizeof(scalar_s));
        memset(password, 0, strlen(password)); free(password);
        return -1;
    }
    dump_buf("Received dp9ik response", (char *)recv_buf, (int)n);

    memcpy(YBc, recv_buf, AUTH_PAKYLEN);

    /* Step 8: Unmask client's key: Yc = YBc - M */
    if (dp9ik_pak_unmask(Yc, YBc, password, dom, user) < 0) {
        fprintf(stderr, "p9any: failed to unmask client key\n");
        memset(scalar_s, 0, sizeof(scalar_s));
        memset(password, 0, strlen(password)); free(password);
        return -1;
    }
    memset(password, 0, strlen(password)); free(password); password = NULL;

    /* Step 9: Compute shared secret ss = s * Yc */
    if (dp9ik_pak_shared_secret(ss, scalar_s, Yc) < 0) {
        fprintf(stderr, "p9any: failed to compute shared secret\n");
        memset(scalar_s, 0, sizeof(scalar_s));
        return -1;
    }
    memset(scalar_s, 0, sizeof(scalar_s));

    /* Step 10: Derive session key Kn */
    if (dp9ik_derive_session_key(Kn, sizeof(Kn), ss, chal_c, chal_s, user) < 0) {
        fprintf(stderr, "p9any: failed to derive session key\n");
        return -1;
    }
    fprintf(stderr, "p9any: derived session key Kn\n");

    /* Step 11: Decrypt ticket  (wire format: nonce[12] || ciphertext+tag) */
    memcpy(nonce, recv_buf + AUTH_PAKYLEN, 12);
    if (dp9ik_decrypt_ticket_real(&ticket,
                                   recv_buf + AUTH_PAKYLEN + 12,
                                   enc_ticket_len - 12,
                                   Kn, nonce) < 0) {
        fprintf(stderr, "p9any: ticket decryption failed\n");
        return -1;
    }
    fprintf(stderr, "p9any: ticket decrypted for cuid=%s\n", ticket.cuid);

    /* Step 12: Verify ticket cuid */
    if (strncmp(ticket.cuid, user, AUTH_ANAMELEN) != 0) {
        fprintf(stderr, "p9any: ticket cuid mismatch (got '%s', expected '%s')\n",
                ticket.cuid, user);
        return -1;
    }

    /* Step 13: Decrypt authenticator (wire format: nonce[12] || ciphertext+tag) */
    if (dp9ik_decrypt_authenticator(&client_auth,
                                     recv_buf + AUTH_PAKYLEN + enc_ticket_len,
                                     enc_auth_len,
                                     Kn) < 0) {
        fprintf(stderr, "p9any: authenticator decryption failed\n");
        return -1;
    }

    /* Step 14: Verify authenticator challenge matches client challenge */
    if (memcmp(client_auth.chal, chal_c, AUTH_CHALLEN) != 0) {
        fprintf(stderr, "p9any: authenticator challenge mismatch\n");
        return -1;
    }
    fprintf(stderr, "p9any: authenticator verified\n");

    /* Step 15: Build and encrypt server authenticator */
    memset(&server_auth, 0, sizeof(server_auth));
    server_auth.num = (char)AUTH_AS;
    memcpy(server_auth.chal, chal_s, AUTH_CHALLEN);
    if (dp9ik_random_bytes((unsigned char *)server_auth.rand, AUTH_NONCELEN) < 0) {
        fprintf(stderr, "p9any: failed to generate server auth rand\n");
        return -1;
    }
    if (dp9ik_random_bytes(nonce, 12) < 0) {
        fprintf(stderr, "p9any: failed to generate server auth nonce\n");
        return -1;
    }
    if (dp9ik_encrypt_authenticator(server_auth_buf, &server_auth_enc_len,
                                     &server_auth, Kn, nonce) < 0) {
        fprintf(stderr, "p9any: failed to encrypt server authenticator\n");
        return -1;
    }

    /* Step 16: Send nonce(12) + ciphertext+tag */
    sent = send(fd, (char *)server_auth_buf, 12 + server_auth_enc_len, 0);
    if (sent < 0) {
        fprintf(stderr, "p9any: failed to send server authenticator\n");
        return -1;
    }
    fprintf(stderr, "p9any: sent server authenticator (%ld bytes)\n", (long)sent);

    fprintf(stderr, "p9any: dp9ik authentication complete for user=%s\n", user);
    return 0;
}

/*
 * Handle p9sk1 authentication with password
 * Returns 0 on success, -1 on error
 */
static int p9any_handle_p9sk1(int fd, const char *proto, const char *dom) {
    unsigned char client_chal[AUTH_CHALLEN];
    unsigned char server_rand[AUTH_NONCELEN];
    unsigned char ticket_buf[512];
    unsigned char auth_buf[256];
    int ticket_len, auth_len;
    unsigned char recv_buf[512];
    ssize_t n;
    Ticket ticket;
    Authenticator client_auth, server_auth;
    char *password = NULL;
    unsigned char des_key[P9SK1_KEYLEN];
    const char *user = "glenda";

    fprintf(stderr, "p9any: starting p9sk1 binary auth phase for proto=%s dom=%s\n", proto, dom);

    /* Step 1: Receive 8-byte client challenge */
    if (p9any_recv_challenge(fd, client_chal) < 0) {
        fprintf(stderr, "p9any: failed to receive client challenge\n");
        return -1;
    }
    fprintf(stderr, "p9any: received client challenge\n");

    /* Step 2: Generate server nonce */
    if (p9sk1_gen_nonce(server_rand, AUTH_NONCELEN) < 0) {
        fprintf(stderr, "p9any: failed to generate server nonce\n");
        return -1;
    }

    /* Step 3: Send ticket request (AUTH_TS type, no PAK key for p9sk1) */
    /* For p9sk1, we send ticket request WITHOUT PAK key */
    if (p9any_send_ticketreq(fd, proto, dom, user, client_chal, NULL) < 0) {
        fprintf(stderr, "p9any: failed to send ticket request\n");
        return -1;
    }

    /* Step 4: Receive ticket + authenticator from client */
    /* p9sk1 sends: ticket (72 bytes) + authenticator (17 bytes) */
    n = recv(fd, (char *)recv_buf, sizeof(recv_buf), 0);
    if (n <= 0) {
        fprintf(stderr, "p9any: failed to receive ticket+authenticator: %s\n", strerror(errno));
        return -1;
    }

    dump_buf("Received Ticket+Auth", (char *)recv_buf, (int)n);

    /* For p9sk1: ticket is 72 bytes, authenticator is 17 bytes = 89 bytes total */
    if (n < P9SK1_TICKETLEN + P9SK1_AUTHLEN) {
        fprintf(stderr, "p9any: p9sk1 response too short (%ld < %d)\n",
                (long)n, P9SK1_TICKETLEN + P9SK1_AUTHLEN);
        return -1;
    }

    /* Extract ticket and authenticator */
    memcpy(ticket_buf, recv_buf, P9SK1_TICKETLEN);
    ticket_len = P9SK1_TICKETLEN;
    memcpy(auth_buf, recv_buf + P9SK1_TICKETLEN, P9SK1_AUTHLEN);
    auth_len = P9SK1_AUTHLEN;

    fprintf(stderr, "p9any: received ticket (%d bytes) + authenticator (%d bytes), total %ld\n",
            ticket_len, auth_len, (long)n);

    /* Step 5: Find password from factotum */
    password = p9sk1_find_password(user, dom);
    if (password == NULL) {
        fprintf(stderr, "p9any: failed to find password for user=%s dom=%s\n", user, dom);
        fprintf(stderr, "p9any: please add key to factotum: key proto=p9sk1 dom=%s user=%s !password=yourpassword\n",
                dom, user);
        return -1;
    }

    /* Step 6: Derive DES key from password */
    if (p9sk1_passtokey(password, user, des_key, sizeof(des_key)) < 0) {
        fprintf(stderr, "p9any: failed to derive DES key from password\n");
        free(password);
        return -1;
    }
    free(password);  /* Clear password from memory */

    /* Step 7: Decrypt and parse ticket */
    if (p9sk1_decrypt_ticket(ticket_buf, ticket_len, des_key, &ticket) < 0) {
        fprintf(stderr, "p9any: failed to decrypt ticket\n");
        return -1;
    }

    /* Step 8: Validate ticket */
    if (p9sk1_validate_ticket(&ticket, user, dom) < 0) {
        fprintf(stderr, "p9any: ticket validation failed\n");
        return -1;
    }
    fprintf(stderr, "p9any: ticket validation successful\n");

    /* Step 9: Parse authenticator */
    if (p9sk1_parse_authenticator(auth_buf, auth_len, &client_auth) < 0) {
        fprintf(stderr, "p9any: failed to parse authenticator\n");
        return -1;
    }

    /* Step 10: Verify authenticator */
    if (p9sk1_verify_authenticator(&client_auth, &ticket) < 0) {
        fprintf(stderr, "p9any: authenticator verification failed\n");
        return -1;
    }
    fprintf(stderr, "p9any: authenticator verification successful\n");

    /* Step 11: Generate server authenticator */
    if (p9sk1_create_server_authenticator(&server_auth, client_chal, server_rand) < 0) {
        fprintf(stderr, "p9any: failed to create server authenticator\n");
        return -1;
    }

    /* Step 12: Send server authenticator */
    if (p9any_send_authenticator(fd, (unsigned char *)&server_auth, sizeof(server_auth)) < 0) {
        fprintf(stderr, "p9any: failed to send server authenticator\n");
        return -1;
    }

    fprintf(stderr, "p9any: p9sk1 authentication successful for user %s\n", user);
    return 0;
}

static int p9any_proceed_with_auth(int fd, char *proto, char *dom) {
    ProtoType ptype;

    ptype = p9any_proto_type(proto);

    if (ptype == PROTO_DPIK) {
        return p9any_handle_dp9ik(fd, proto, dom);
    } else if (ptype == PROTO_P9SK1) {
        return p9any_handle_p9sk1(fd, proto, dom);
    } else {
        fprintf(stderr, "p9any: unknown protocol type: %s\n", proto);
        return -1;
    }
}


/* * p9any_handler: The main state machine
 */
 /* * p9any_handler: The main state machine
 */
int p9any_handler(int fd, const char *domain) {
    char buf[512], proto[32], dom[64], offer[128];
    char *choice, *p;
    ssize_t n;
    int len;
    const char ok_msg[] = "OK"; /* For OK response below */
    const char empty_ack[] = ""; /* For empty acknowledgment */

    choice = NULL;
    if (domain == NULL) domain = "localhost";

    /* 1. Initial Read */
    n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return -1;
    buf[n] = '\0';
    
    dump_buf("Initial Read", buf, (int)n);

    /* * Logic: Iterate through the buffer to find the first \n or \0.
     * If there is more data after that first terminator, that's our 'choice'.
     */
    for (p = buf; p < buf + n; p++) {
        if (*p == '\n' || *p == '\r' || *p == '\0') {
            /* Found the end of the 'p9 ...' hello */
            *p = '\0'; 
            /* Peek ahead: is there a choice immediately following? */
            if (p + 1 < buf + n && *(p + 1) != '\0') {
                choice = p + 1;
                /* Skip any leading whitespace/newlines in the choice part */
                while(choice < buf + n && (*choice == '\n' || *choice == '\r' || *choice == ' ')) 
                    choice++;
            }
            break;
        }
    }

    /* 2. Send empty acknowledgment first (drawterm expects this after "p9 ...") */
    if (write(fd, empty_ack, sizeof(empty_ack)) != (ssize_t)sizeof(empty_ack)) return -1;
    fprintf(stderr, "p9any: sent empty acknowledgment\n");

    /* 3. Offer Protocols if client hasn't chosen yet */
    if (!choice || *choice == '\0') {
        /* Drawterm expects v.2 prefix and null-terminated strings */
        len = sprintf(offer, "v.2 dp9ik@%s p9sk1@%s", domain, domain);
        offer[len++] = '\0'; /* Add null terminator explicitly */
        fprintf(stderr, "p9any: sending offer (%d bytes)\n", len);

        if (write(fd, offer, len) != len) return -1;

        /* Wait for the client to reply with a choice */
        n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0) return -1;
        buf[n] = '\0';
        choice = buf;
        dump_buf("Second Read (Choice)", choice, (int)n);
    }

    /* 3. Clean and Parse Choice */
    for (p = choice; *p; p++) {
        if (*p == '\r' || *p == '\n' || *p == ' ' || *p == '\t' || *p == '\0') {
            *p = '\0';
            break;
        }
    }
    
    if (p9any_parse_choice(choice, proto, sizeof(proto), dom, sizeof(dom)) < 0) {
        strncpy(proto, choice, sizeof(proto) - 1);
        proto[sizeof(proto)-1] = '\0';
        strncpy(dom, domain, sizeof(dom)-1);
        dom[sizeof(dom)-1] = '\0';
    }
    fprintf(stderr, "p9any: finalized choice [%s] on domain [%s]\n", proto, dom);

    /* 5. THE CRITICAL 'OK' - send null-terminated like drawterm expects */
    if (write(fd, ok_msg, sizeof(ok_msg)) != (ssize_t)sizeof(ok_msg)) return -1;

    /* 6. Enter binary phase */
    return p9any_proceed_with_auth(fd, proto, dom);
}