/*
 * Kryon Authentication - p9sk1 (DES-based Password Authentication)
 * C89/C90 compliant
 *
 * Based on Plan 9 p9sk1 authentication protocol
 */

#include "auth_p9sk1.h"
#include "devfactotum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef USE_OPENSSL
#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#else
/* Fallback implementations */
#define DES_key_schedule void
#define DES_cblock unsigned char[8]
#define RAND_bytes(buf, len) (-1)
#define MD5_DIGEST_LENGTH 16
#endif

/*
 * Simple MD5 fallback (for systems without OpenSSL)
 * This is a simplified MD5 - in production, use OpenSSL
 */
#ifdef USE_OPENSSL

static void md5_hash(const unsigned char *data, size_t len,
                     unsigned char *hash)
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, len);
    MD5_Final(hash, &ctx);
}

#else

/* Very weak fallback hash - DO NOT USE IN PRODUCTION */
static void md5_hash(const unsigned char *data, size_t len,
                     unsigned char *hash)
{
    size_t i;
    unsigned int sum = 0;

    for (i = 0; i < len; i++) {
        sum = (sum << 1) ^ data[i];
    }

    /* Fill 16-byte hash output */
    for (i = 0; i < 16; i++) {
        hash[i] = (unsigned char)((sum + i) & 0xFF);
    }
}

#endif

/*
 * Set odd parity on DES key
 * DES requires odd parity on each byte (least significant bit is parity)
 */
void p9sk1_des_set_parity(unsigned char *key, size_t len)
{
    size_t i, j;
    unsigned char b;
    unsigned int bitcount;

    for (i = 0; i < len; i++) {
        b = key[i];
        /* Count bits in high 7 bits */
        bitcount = 0;
        for (j = 0; j < 7; j++) {
            if (b & (1 << j)) {
                bitcount++;
            }
        }
        /* Set parity bit to make total odd */
        if (bitcount % 2 == 0) {
            key[i] = b | 0x01;  /* Set LSB for odd parity */
        } else {
            key[i] = b & 0xFE;  /* Clear LSB for odd parity */
        }
    }
}

/*
 * Expand Plan 9 7-byte compact DES key to 8-byte DES key.
 * Plan 9 stores DES keys as 56 bits packed without parity bits.
 * OpenSSL expects 8 bytes where each byte has 7 key bits (MSBs) + 1 parity bit (LSB).
 * The 56 key bits are distributed 7 bits per byte: k8[d] bits 7..1 = k7 bits d*7..(d*7+6).
 */
static void expand_des_key7to8(const unsigned char *k7, unsigned char *k8)
{
    int d, b;
    int src_idx;

    memset(k8, 0, 8);
    for (d = 0; d < 8; d++) {
        for (b = 0; b < 7; b++) {
            src_idx = d * 7 + b;
            if (k7[src_idx / 8] & (0x80 >> (src_idx % 8))) {
                k8[d] |= (0x80 >> b);
            }
        }
        /* bit 0 (LSB) is left as 0 — DES_set_odd_parity will correct it */
    }
}

/*
 * Convert password to DES key using Plan 9's passtokey algorithm.
 * From Plan 9 libc/port/passtokey.c:
 *   XOR-cycle each password byte into a 7-byte buffer (no username, no hashing).
 * The 7-byte compact key is then expanded to the 8-byte DES format OpenSSL expects.
 */
int p9sk1_passtokey(const char *password, const char *username,
                    unsigned char *des_key, size_t keylen)
{
    unsigned char k7[7];
    int i;
    const char *p;

    (void)username; /* Plan 9's passtokey does not use the username */

    if (password == NULL || des_key == NULL || keylen < P9SK1_KEYLEN) {
        return -1;
    }

    /* XOR-cycle password bytes into 7-byte buffer */
    memset(k7, 0, sizeof(k7));
    for (p = password, i = 0; *p != '\0'; p++, i++) {
        k7[i % 7] ^= (unsigned char)*p;
    }

    /* Expand to 8-byte OpenSSL DES key format */
    expand_des_key7to8(k7, des_key);

    /* Zero the intermediate key material */
    memset(k7, 0, sizeof(k7));

    /* Set odd parity on each byte (bit 0) */
    p9sk1_des_set_parity(des_key, P9SK1_KEYLEN);

    fprintf(stderr, "p9sk1: derived DES key from password (Plan 9 passtokey)\n");

    return 0;
}

/*
 * Find password key from the in-memory factotum key store.
 * Loaded from /etc/marrow/keys at startup via factotum_load_keys().
 */
char *p9sk1_find_password(const char *user, const char *dom)
{
    FactotumKey *key;
    const char *pw;
    char *result;
    size_t pwlen;

    if (user == NULL) {
        fprintf(stderr, "p9sk1_find_password: NULL user\n");
        return NULL;
    }

    key = factotum_find_key("p9sk1", dom, user);
    if (key == NULL) {
        fprintf(stderr, "p9sk1_find_password: no key for user=%s dom=%s\n",
                user, dom ? dom : "*");
        return NULL;
    }

    pw = factotum_get_attr(key->privattr, "password");
    if (pw == NULL) {
        fprintf(stderr, "p9sk1_find_password: key has no !password attr\n");
        return NULL;
    }

    pwlen = strlen(pw);
    result = (char *)malloc(pwlen + 1);
    if (result == NULL) return NULL;
    memcpy(result, pw, pwlen + 1);

    fprintf(stderr, "p9sk1: found password for user=%s\n", user);
    return result;
}

#ifdef USE_OPENSSL

/*
 * Encrypt buffer using DES ECB mode
 */
int p9sk1_des_ecb_encrypt(const unsigned char *plaintext,
                          unsigned char *ciphertext,
                          int len, const unsigned char *key)
{
    DES_cblock des_key;
    DES_key_schedule schedule;
    int i;

    if (plaintext == NULL || ciphertext == NULL || key == NULL) {
        return -1;
    }

    if (len % 8 != 0) {
        fprintf(stderr, "p9sk1_des_ecb_encrypt: length must be multiple of 8\n");
        return -1;
    }

    /* Copy key and set parity */
    memcpy(des_key, key, 8);
    DES_set_odd_parity(&des_key);
    DES_set_key_checked(&des_key, &schedule);

    /* Encrypt each 8-byte block */
    for (i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(plaintext + i),
                        (DES_cblock *)(ciphertext + i),
                        &schedule, DES_ENCRYPT);
    }

    return 0;
}

/*
 * Decrypt buffer using DES ECB mode
 */
int p9sk1_des_ecb_decrypt(const unsigned char *ciphertext,
                          unsigned char *plaintext,
                          int len, const unsigned char *key)
{
    DES_cblock des_key;
    DES_key_schedule schedule;
    int i;

    if (ciphertext == NULL || plaintext == NULL || key == NULL) {
        return -1;
    }

    if (len % 8 != 0) {
        fprintf(stderr, "p9sk1_des_ecb_decrypt: length must be multiple of 8\n");
        return -1;
    }

    /* Copy key and set parity */
    memcpy(des_key, key, 8);
    DES_set_odd_parity(&des_key);
    DES_set_key_checked(&des_key, &schedule);

    /* Decrypt each 8-byte block */
    for (i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciphertext + i),
                        (DES_cblock *)(plaintext + i),
                        &schedule, DES_DECRYPT);
    }

    return 0;
}

#else

/*
 * Weak fallback XOR encryption (DO NOT USE IN PRODUCTION)
 */
static void xor_crypt(const unsigned char *in, unsigned char *out, int len,
                      const unsigned char *key)
{
    int i;
    unsigned char k = key[0];

    for (i = 0; i < len; i++) {
        out[i] = in[i] ^ k;
        k = (k << 1) | (k >> 7);  /* Rotate */
    }
}

int p9sk1_des_ecb_encrypt(const unsigned char *plaintext,
                          unsigned char *ciphertext,
                          int len, const unsigned char *key)
{
    if (plaintext == NULL || ciphertext == NULL || key == NULL) {
        return -1;
    }
    xor_crypt(plaintext, ciphertext, len, key);
    return 0;
}

int p9sk1_des_ecb_decrypt(const unsigned char *ciphertext,
                          unsigned char *plaintext,
                          int len, const unsigned char *key)
{
    if (ciphertext == NULL || plaintext == NULL || key == NULL) {
        return -1;
    }
    /* XOR is symmetric */
    xor_crypt(ciphertext, plaintext, len, key);
    return 0;
}

#endif

/*
 * Decrypt ticket using DES key
 * Ticket format: num(1) + chal(8) + cuid(28) + suid(28) + key(7)
 * Total: 72 bytes
 */
int p9sk1_decrypt_ticket(const unsigned char *encrypted, int enc_len,
                         const unsigned char *des_key,
                         Ticket *t)
{
    unsigned char decrypted[P9SK1_TICKETLEN];
    int key_offset;

    if (encrypted == NULL || des_key == NULL || t == NULL) {
        fprintf(stderr, "p9sk1_decrypt_ticket: NULL parameter\n");
        return -1;
    }

    if (enc_len < P9SK1_TICKETLEN) {
        fprintf(stderr, "p9sk1_decrypt_ticket: buffer too short (%d < %d)\n",
                enc_len, P9SK1_TICKETLEN);
        return -1;
    }

    /* Decrypt using DES ECB */
    if (p9sk1_des_ecb_decrypt(encrypted, decrypted, P9SK1_TICKETLEN, des_key) < 0) {
        fprintf(stderr, "p9sk1_decrypt_ticket: DES decryption failed\n");
        return -1;
    }

    /* Parse ticket structure */
    memset(t, 0, sizeof(Ticket));

    t->num = decrypted[0];
    memcpy(t->chal, decrypted + 1, AUTH_CHALLEN);
    memcpy(t->cuid, decrypted + 1 + AUTH_CHALLEN, AUTH_ANAMELEN);
    memcpy(t->suid, decrypted + 1 + AUTH_CHALLEN + AUTH_ANAMELEN, AUTH_ANAMELEN);

    /* Key is 7 bytes in p9sk1 (56-bit DES key) */
    key_offset = 1 + AUTH_CHALLEN + 2 * AUTH_ANAMELEN;
    memset(t->key, 0, sizeof(t->key));
    memcpy(t->key, decrypted + key_offset, 7);

    fprintf(stderr, "p9sk1: decrypted ticket for user=%s server=%s\n",
            t->cuid, t->suid);

    return 0;
}

/*
 * Validate ticket structure
 */
int p9sk1_validate_ticket(const Ticket *t, const char *expected_user,
                          const char *expected_dom)
{
    int i;

    if (t == NULL) {
        fprintf(stderr, "p9sk1_validate_ticket: NULL ticket\n");
        return -1;
    }

    /* Check that cuid is not all zeros */
    for (i = 0; i < AUTH_ANAMELEN && t->cuid[i] == '\0'; i++) {
        /* Continue checking */
    }
    if (i == AUTH_ANAMELEN) {
        fprintf(stderr, "p9sk1_validate_ticket: empty cuid\n");
        return -1;
    }

    /* Check that suid is not all zeros */
    for (i = 0; i < AUTH_ANAMELEN && t->suid[i] == '\0'; i++) {
        /* Continue checking */
    }
    if (i == AUTH_ANAMELEN) {
        fprintf(stderr, "p9sk1_validate_ticket: empty suid\n");
        return -1;
    }

    /* Verify cuid matches expected user */
    if (expected_user != NULL) {
        if (strncmp(t->cuid, expected_user, AUTH_ANAMELEN) != 0) {
            fprintf(stderr, "p9sk1_validate_ticket: cuid mismatch (got %s, expected %s)\n",
                    t->cuid, expected_user);
            return -1;
        }
    }

    /* Check that challenge is not all zeros */
    for (i = 0; i < AUTH_CHALLEN && t->chal[i] == '\0'; i++) {
        /* Continue checking */
    }
    if (i == AUTH_CHALLEN) {
        fprintf(stderr, "p9sk1_validate_ticket: empty challenge\n");
        return -1;
    }

    fprintf(stderr, "p9sk1: ticket validated for user=%s\n", t->cuid);

    /* Domain check is informational */
    if (expected_dom != NULL) {
        fprintf(stderr, "p9sk1: ticket domain=%s (expected=%s)\n", t->suid, expected_dom);
    }

    return 0;
}

/*
 * Parse authenticator from buffer
 * Authenticator format: num(1) + chal(8) + id(8)
 * Total: 17 bytes
 */
int p9sk1_parse_authenticator(const unsigned char *buf, int len,
                              Authenticator *a)
{
    if (buf == NULL || a == NULL) {
        fprintf(stderr, "p9sk1_parse_authenticator: NULL parameter\n");
        return -1;
    }

    if (len < P9SK1_AUTHLEN) {
        fprintf(stderr, "p9sk1_parse_authenticator: buffer too short (%d < %d)\n",
                len, P9SK1_AUTHLEN);
        return -1;
    }

    memset(a, 0, sizeof(Authenticator));

    a->num = buf[0];
    memcpy(a->chal, buf + 1, AUTH_CHALLEN);
    /* Remaining 8 bytes go to rand field */
    memcpy(a->rand, buf + 1 + AUTH_CHALLEN, AUTH_NONCELEN);

    fprintf(stderr, "p9sk1: parsed authenticator\n");

    return 0;
}

/*
 * Verify authenticator
 */
int p9sk1_verify_authenticator(const Authenticator *a,
                               const Ticket *t)
{
    int i;

    if (a == NULL || t == NULL) {
        fprintf(stderr, "p9sk1_verify_authenticator: NULL parameter\n");
        return -1;
    }

    /* Check that challenge matches ticket's challenge */
    if (memcmp(a->chal, t->chal, AUTH_CHALLEN) != 0) {
        fprintf(stderr, "p9sk1_verify_authenticator: challenge mismatch\n");
        return -1;
    }

    /* Check that rand is not all zeros */
    for (i = 0; i < AUTH_NONCELEN && a->rand[i] == '\0'; i++) {
        /* Continue checking */
    }
    if (i == AUTH_NONCELEN) {
        fprintf(stderr, "p9sk1_verify_authenticator: empty random nonce\n");
        return -1;
    }

    fprintf(stderr, "p9sk1: authenticator verified\n");

    return 0;
}

/*
 * Generate server authenticator
 */
int p9sk1_create_server_authenticator(Authenticator *a,
                                     const unsigned char *client_chal,
                                     const unsigned char *server_rand)
{
    if (a == NULL || client_chal == NULL || server_rand == NULL) {
        return -1;
    }

    memset(a, 0, sizeof(Authenticator));

    a->num = 0;  /* TODO: proper counter/replay protection */
    memcpy(a->chal, client_chal, AUTH_CHALLEN);
    memcpy(a->rand, server_rand, AUTH_NONCELEN);

    fprintf(stderr, "p9sk1: created server authenticator\n");

    return 0;
}

/*
 * Generate random nonce
 */
int p9sk1_gen_nonce(unsigned char *nonce, size_t len)
{
#ifdef USE_OPENSSL
    if (RAND_bytes(nonce, len) != 1) {
        fprintf(stderr, "p9sk1_gen_nonce: RAND_bytes failed\n");
        return -1;
    }
    return 0;
#else
    /* Fallback: use simple pseudo-random */
    size_t i;
    static int seeded = 0;

    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }

    for (i = 0; i < len; i++) {
        nonce[i] = (unsigned char)(rand() & 0xFF);
    }

    return 0;
#endif
}
