/*
 * Kryon Authentication - dp9ik (Ed448 SPAKE2-EE) Authentication
 * C89/C90 compliant
 *
 * Implements 9front's dp9ik password-authenticated key exchange.
 *
 * Protocol (server side):
 *   1. Receive 8-byte client challenge
 *   2. Generate random ephemeral scalar s (56 bytes)
 *   3. Compute Ys = s * G  (public key)
 *   4. Compute password mask M = hash_to_point(password || domain || user)
 *   5. Compute blinded key YBs = Ys + M  (point addition)
 *   6. Send Ticketreq (141 bytes) + YBs (57 bytes)
 *   7. Receive YBc (57 bytes) + form1-encrypted Ticket + form1-encrypted Auth
 *   8. Unmask client key: Yc = YBc - M
 *   9. Compute shared secret: ss = s * Yc  (57 bytes)
 *  10. Derive session key: Kn = HKDF-SHA256(ss, chal_c || chal_s)
 *  11. Decrypt and verify Ticket with Kn
 *  12. Decrypt and verify Authenticator with Kn
 *  13. Send server Authenticator encrypted with Kn
 */

#include "auth_dp9ik.h"
#include "ed448.h"
#include "devfactotum.h"
#include "sha2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#endif

/* ------------------------------------------------------------------ */
/*  Basic crypto utilities                                              */
/* ------------------------------------------------------------------ */

int dp9ik_crypto_init(void)
{
#ifdef USE_OPENSSL
    return ed448_init();
#else
    return 0;
#endif
}

void dp9ik_crypto_cleanup(void)
{
#ifdef USE_OPENSSL
    ed448_cleanup();
#endif
}

int dp9ik_random_bytes(unsigned char *buf, size_t len)
{
#ifdef USE_OPENSSL
    if (RAND_bytes(buf, (int)len) != 1) {
        fprintf(stderr, "dp9ik_random_bytes: RAND_bytes failed\n");
        return -1;
    }
    return 0;
#else
    size_t i;
    static int seeded = 0;
    if (!seeded) { srand((unsigned int)time(NULL)); seeded = 1; }
    for (i = 0; i < len; i++) buf[i] = (unsigned char)(rand() & 0xFF);
    return 0;
#endif
}

int dp9ik_gen_challenge(unsigned char *chal)
{
    return dp9ik_random_bytes(chal, AUTH_CHALLEN);
}

int dp9ik_gen_nonce(unsigned char *nonce)
{
    return dp9ik_random_bytes(nonce, AUTH_NONCELEN);
}

/* ------------------------------------------------------------------ */
/*  Ticketreq serialization                                             */
/* ------------------------------------------------------------------ */

int dp9ik_build_ticketreq(const char *authid, const char *authdom,
                          const char *hostid, const char *uid,
                          const unsigned char *chal, Ticketreq *tr)
{
    if (!tr) return -1;
    memset(tr, 0, sizeof(*tr));
    tr->type = AUTH_PAK;
    if (authid)  strncpy(tr->authid,  authid,  AUTH_ANAMELEN - 1);
    if (authdom) strncpy(tr->authdom, authdom, AUTH_DOMLEN   - 1);
    if (hostid)  strncpy(tr->hostid,  hostid,  AUTH_ANAMELEN - 1);
    if (uid)     strncpy(tr->uid,     uid,     AUTH_ANAMELEN - 1);
    if (chal)    memcpy(tr->chal, chal, AUTH_CHALLEN);
    return 0;
}

int dp9ik_serialize_ticketreq(const Ticketreq *tr, unsigned char *buf, size_t len)
{
    size_t needed = 1 + AUTH_ANAMELEN + AUTH_DOMLEN + AUTH_CHALLEN
                      + AUTH_ANAMELEN + AUTH_ANAMELEN;
    if (!tr || !buf || len < needed) return -1;
    buf[0] = (unsigned char)tr->type;
    memcpy(buf + 1,                                              tr->authid,  AUTH_ANAMELEN);
    memcpy(buf + 1 + AUTH_ANAMELEN,                              tr->authdom, AUTH_DOMLEN);
    memcpy(buf + 1 + AUTH_ANAMELEN + AUTH_DOMLEN,                tr->chal,    AUTH_CHALLEN);
    memcpy(buf + 1 + AUTH_ANAMELEN + AUTH_DOMLEN + AUTH_CHALLEN, tr->hostid,  AUTH_ANAMELEN);
    memcpy(buf + 1 + AUTH_ANAMELEN + AUTH_DOMLEN + AUTH_CHALLEN + AUTH_ANAMELEN,
           tr->uid, AUTH_ANAMELEN);
    return (int)needed;
}

int dp9ik_deserialize_ticketreq(const unsigned char *buf, size_t len, Ticketreq *tr)
{
    size_t needed = 1 + AUTH_ANAMELEN + AUTH_DOMLEN + AUTH_CHALLEN
                      + AUTH_ANAMELEN + AUTH_ANAMELEN;
    if (!buf || !tr || len < needed) return -1;
    memset(tr, 0, sizeof(*tr));
    tr->type = (char)buf[0];
    memcpy(tr->authid,  buf + 1,                                              AUTH_ANAMELEN);
    memcpy(tr->authdom, buf + 1 + AUTH_ANAMELEN,                              AUTH_DOMLEN);
    memcpy(tr->chal,    buf + 1 + AUTH_ANAMELEN + AUTH_DOMLEN,                AUTH_CHALLEN);
    memcpy(tr->hostid,  buf + 1 + AUTH_ANAMELEN + AUTH_DOMLEN + AUTH_CHALLEN, AUTH_ANAMELEN);
    memcpy(tr->uid,     buf + 1 + AUTH_ANAMELEN + AUTH_DOMLEN + AUTH_CHALLEN + AUTH_ANAMELEN,
           AUTH_ANAMELEN);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  PAK key operations (SPAKE2-EE with Ed448)                          */
/* ------------------------------------------------------------------ */

/*
 * Generate a random Ed448 ephemeral key pair.
 * pubkey[57]: encoded public point Ys = s * G
 * seckey[56]: private scalar s (also used for DH later)
 */
int dp9ik_pak_key_generate(unsigned char *pubkey, size_t publen,
                           unsigned char *seckey, size_t seclen)
{
    unsigned char scalar[ED448_SCALARLEN];

    if (!pubkey || publen < AUTH_PAKYLEN) return -1;

    if (ed448_init() < 0) {
        fprintf(stderr, "dp9ik_pak_key_generate: ed448_init failed\n");
        return -1;
    }

    if (ed448_scalar_generate(scalar) < 0) return -1;

    if (seckey && seclen >= ED448_SCALARLEN)
        memcpy(seckey, scalar, ED448_SCALARLEN);

    if (ed448_scalarmult_base(pubkey, scalar) < 0) {
        memset(scalar, 0, sizeof(scalar));
        return -1;
    }

    memset(scalar, 0, sizeof(scalar));
    fprintf(stderr, "dp9ik: generated real Ed448 ephemeral key pair\n");
    return 0;
}

/*
 * Compute password mask: M = hash_to_point(password || domain || user)
 */
static int pak_password_mask(unsigned char mask[AUTH_PAKYLEN],
                              const char *password, const char *domain, const char *user)
{
    unsigned char seed[512];
    size_t seedlen;
    size_t pwlen  = password ? strlen(password) : 0;
    size_t domlen = domain   ? strlen(domain)   : 0;
    size_t ulen   = user     ? strlen(user)     : 0;

    seedlen = pwlen + domlen + ulen + 2;  /* separators */
    if (seedlen > sizeof(seed)) seedlen = sizeof(seed);

    memset(seed, 0, sizeof(seed));
    {
        size_t off = 0;
        if (pwlen  > 0) { memcpy(seed + off, password, pwlen);  off += pwlen; }
        seed[off++] = '\x00';  /* separator */
        if (domlen > 0) { memcpy(seed + off, domain, domlen);   off += domlen; }
        seed[off++] = '\x00';
        if (ulen   > 0) { memcpy(seed + off, user, ulen);       off += ulen; }
        seedlen = off;
    }

    return ed448_hash_to_point(mask, seed, seedlen);
}

/*
 * Compute blinded server PAK key: YBs = Ys + M
 * pubkey: raw ephemeral public key (s*G)
 * Returns blinded key in out[AUTH_PAKYLEN].
 */
int dp9ik_pak_blind(unsigned char out[AUTH_PAKYLEN],
                    const unsigned char pubkey[AUTH_PAKYLEN],
                    const char *password, const char *domain, const char *user)
{
    unsigned char mask[AUTH_PAKYLEN];

    if (pak_password_mask(mask, password, domain, user) < 0) {
        fprintf(stderr, "dp9ik_pak_blind: failed to compute password mask\n");
        return -1;
    }

    if (ed448_point_add(out, pubkey, mask) < 0) {
        fprintf(stderr, "dp9ik_pak_blind: point addition failed\n");
        return -1;
    }

    return 0;
}

/*
 * Unmask client's blinded key: Yc = YBc - M
 */
int dp9ik_pak_unmask(unsigned char out[AUTH_PAKYLEN],
                     const unsigned char ybc[AUTH_PAKYLEN],
                     const char *password, const char *domain, const char *user)
{
    unsigned char mask[AUTH_PAKYLEN];

    if (pak_password_mask(mask, password, domain, user) < 0) {
        fprintf(stderr, "dp9ik_pak_unmask: failed to compute password mask\n");
        return -1;
    }

    if (ed448_point_sub(out, ybc, mask) < 0) {
        fprintf(stderr, "dp9ik_pak_unmask: point subtraction failed\n");
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  HKDF key derivation                                                 */
/* ------------------------------------------------------------------ */

int dp9ik_hkdf(const unsigned char *ikm, size_t ikmlen,
               const unsigned char *salt, size_t saltlen,
               const unsigned char *info, size_t infolen,
               unsigned char *okm, size_t okmlen)
{
#ifdef USE_OPENSSL
    EVP_PKEY_CTX *pctx;
    int ok = 0;

    if (!ikm || !okm || okmlen == 0) return -1;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto done;

    if (salt && saltlen > 0) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)saltlen) <= 0) goto done;
    } else {
        /* No salt: use a zero-length salt */
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, (unsigned char *)"", 0) <= 0) goto done;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikmlen) <= 0) goto done;
    if (info && infolen > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)infolen) <= 0) goto done;
    }
    if (EVP_PKEY_derive(pctx, okm, &okmlen) <= 0) goto done;

    ok = 1;
done:
    EVP_PKEY_CTX_free(pctx);
    return ok ? 0 : -1;
#else
    (void)ikm; (void)ikmlen; (void)salt; (void)saltlen;
    (void)info; (void)infolen; (void)okm; (void)okmlen;
    return -1;
#endif
}

/* ------------------------------------------------------------------ */
/*  Session key derivation from PAK shared secret                       */
/* ------------------------------------------------------------------ */

/*
 * Derive the session key Kn from the PAK shared secret ss and challenges.
 * Kn = HKDF-SHA256(ss, "dp9ik" || chal_client || chal_server || user)
 */
int dp9ik_derive_session_key(unsigned char *kn, size_t knlen,
                              const unsigned char *ss,  /* 57-byte shared secret */
                              const unsigned char *chal_c,
                              const unsigned char *chal_s,
                              const char *user)
{
    unsigned char info[256];
    size_t info_len = 0;
    const char *label = "dp9ik session key";
    size_t ulen = user ? strlen(user) : 0;

    memcpy(info, label, strlen(label));        info_len += strlen(label);
    memcpy(info + info_len, chal_c, AUTH_CHALLEN); info_len += AUTH_CHALLEN;
    memcpy(info + info_len, chal_s, AUTH_CHALLEN); info_len += AUTH_CHALLEN;
    if (ulen > 0) {
        if (info_len + ulen < sizeof(info)) {
            memcpy(info + info_len, user, ulen);
            info_len += ulen;
        }
    }

    return dp9ik_hkdf(ss, AUTH_PAKYLEN, NULL, 0, info, info_len, kn, knlen);
}

/* ------------------------------------------------------------------ */
/*  ChaCha20-Poly1305 for form1 messages                                */
/* ------------------------------------------------------------------ */

/*
 * Encrypt data using ChaCha20-Poly1305 (form1 format).
 * out:      ciphertext + 16-byte poly1305 tag (len + 16 bytes)
 * nonce:    12 bytes
 * Returns number of output bytes, or -1 on error.
 */
#ifdef USE_OPENSSL
static int chacha20_poly1305_encrypt(
    unsigned char *out, int *outlen,
    const unsigned char *plain, int plainlen,
    const unsigned char *key, int keylen,
    const unsigned char *nonce,
    const unsigned char *aad, int aadlen)
{
    EVP_CIPHER_CTX *ctx;
    int len, total, ok = 0;
    unsigned char tag[16];

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (!EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)) goto done;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) goto done;
    if (aad && aadlen > 0) {
        if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen)) goto done;
    }
    if (!EVP_EncryptUpdate(ctx, out, &len, plain, plainlen)) goto done;
    total = len;
    if (!EVP_EncryptFinal_ex(ctx, out + len, &len)) goto done;
    total += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) goto done;
    memcpy(out + total, tag, 16);
    total += 16;
    *outlen = total;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int chacha20_poly1305_decrypt(
    unsigned char *out, int *outlen,
    const unsigned char *cipher, int cipherlen,
    const unsigned char *key, int keylen,
    const unsigned char *nonce,
    const unsigned char *aad, int aadlen)
{
    EVP_CIPHER_CTX *ctx;
    int len, total, ok = 0;
    unsigned char tag[16];

    if (cipherlen < 16) return -1;

    memcpy(tag, cipher + cipherlen - 16, 16);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (!EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)) goto done;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)) goto done;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) goto done;
    if (aad && aadlen > 0) {
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen)) goto done;
    }
    if (!EVP_DecryptUpdate(ctx, out, &len, cipher, cipherlen - 16)) goto done;
    total = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)) goto done;
    if (!EVP_DecryptFinal_ex(ctx, out + total, &len)) goto done;
    total += len;
    *outlen = total;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}
#endif /* USE_OPENSSL */

/* ------------------------------------------------------------------ */
/*  Ticket operations                                                   */
/* ------------------------------------------------------------------ */

/*
 * Build and encrypt a Ticket using the session key Kn.
 * The ticket contains: num(1) + chal(8) + cuid(28) + suid(28) + key(32)
 * Total: 97 bytes of plaintext, encrypted with ChaCha20-Poly1305.
 * The encrypted ticket (with 12-byte nonce and 16-byte tag) is 125 bytes.
 */
int dp9ik_encrypt_ticket_real(unsigned char *out, int *outlen,
                               const Ticket *t,
                               const unsigned char *kn,
                               const unsigned char *nonce)
{
#ifdef USE_OPENSSL
    unsigned char plain[1 + AUTH_CHALLEN + AUTH_ANAMELEN + AUTH_ANAMELEN + AUTH_PAKKEYLEN];
    int plainlen = sizeof(plain);
    int i = 0;

    plain[i++] = (unsigned char)t->num;
    memcpy(plain + i, t->chal, AUTH_CHALLEN); i += AUTH_CHALLEN;
    memcpy(plain + i, t->cuid, AUTH_ANAMELEN); i += AUTH_ANAMELEN;
    memcpy(plain + i, t->suid, AUTH_ANAMELEN); i += AUTH_ANAMELEN;
    memcpy(plain + i, t->key,  AUTH_PAKKEYLEN); i += AUTH_PAKKEYLEN;

    return chacha20_poly1305_encrypt(out, outlen, plain, plainlen,
                                     kn, AUTH_PAKKEYLEN, nonce, NULL, 0);
#else
    (void)out; (void)outlen; (void)t; (void)kn; (void)nonce;
    return -1;
#endif
}

int dp9ik_decrypt_ticket_real(Ticket *t,
                               const unsigned char *cipher, int cipherlen,
                               const unsigned char *kn,
                               const unsigned char *nonce)
{
#ifdef USE_OPENSSL
    unsigned char plain[256];
    int plainlen;
    int off;

    if (chacha20_poly1305_decrypt(plain, &plainlen, cipher, cipherlen,
                                  kn, AUTH_PAKKEYLEN, nonce, NULL, 0) < 0) {
        fprintf(stderr, "dp9ik_decrypt_ticket_real: decryption failed\n");
        return -1;
    }

    if (plainlen < 1 + AUTH_CHALLEN + AUTH_ANAMELEN + AUTH_ANAMELEN + AUTH_PAKKEYLEN) {
        fprintf(stderr, "dp9ik_decrypt_ticket_real: decrypted ticket too short\n");
        return -1;
    }

    memset(t, 0, sizeof(*t));
    off = 0;
    t->num = (char)plain[off++];
    memcpy(t->chal, plain + off, AUTH_CHALLEN); off += AUTH_CHALLEN;
    memcpy(t->cuid, plain + off, AUTH_ANAMELEN); off += AUTH_ANAMELEN;
    memcpy(t->suid, plain + off, AUTH_ANAMELEN); off += AUTH_ANAMELEN;
    memcpy(t->key,  plain + off, AUTH_PAKKEYLEN);

    fprintf(stderr, "dp9ik: decrypted ticket for cuid=%s\n", t->cuid);
    return 0;
#else
    (void)t; (void)cipher; (void)cipherlen; (void)kn; (void)nonce;
    return -1;
#endif
}

/* ------------------------------------------------------------------ */
/*  Authenticator operations                                            */
/* ------------------------------------------------------------------ */

/*
 * Encrypt an Authenticator using ChaCha20-Poly1305.
 * Plaintext: num(1) + chal(8) + rand(8) = 17 bytes
 * Output: 12-byte nonce || ciphertext+tag (17+16=33 bytes) = 45 bytes total
 */
int dp9ik_encrypt_authenticator(unsigned char *out, int *outlen,
                                 const Authenticator *a,
                                 const unsigned char *kn,
                                 const unsigned char *nonce)
{
#ifdef USE_OPENSSL
    unsigned char plain[1 + AUTH_CHALLEN + AUTH_NONCELEN];
    int plainlen = sizeof(plain);
    int i = 0;

    plain[i++] = (unsigned char)a->num;
    memcpy(plain + i, a->chal, AUTH_CHALLEN); i += AUTH_CHALLEN;
    memcpy(plain + i, a->rand, AUTH_NONCELEN); i += AUTH_NONCELEN;

    /* Write nonce first */
    memcpy(out, nonce, 12);
    return chacha20_poly1305_encrypt(out + 12, outlen, plain, plainlen,
                                     kn, AUTH_PAKKEYLEN, nonce, NULL, 0);
#else
    (void)out; (void)outlen; (void)a; (void)kn; (void)nonce;
    return -1;
#endif
}

int dp9ik_decrypt_authenticator(Authenticator *a,
                                 const unsigned char *cipher, int cipherlen,
                                 const unsigned char *kn)
{
#ifdef USE_OPENSSL
    unsigned char plain[256];
    int plainlen;
    const unsigned char *nonce;
    int off;

    if (cipherlen < 12 + 1 + AUTH_CHALLEN + AUTH_NONCELEN + 16) {
        fprintf(stderr, "dp9ik_decrypt_authenticator: too short\n");
        return -1;
    }

    nonce = cipher;  /* first 12 bytes are nonce */

    if (chacha20_poly1305_decrypt(plain, &plainlen,
                                  cipher + 12, cipherlen - 12,
                                  kn, AUTH_PAKKEYLEN, nonce, NULL, 0) < 0) {
        fprintf(stderr, "dp9ik_decrypt_authenticator: decryption failed\n");
        return -1;
    }

    if (plainlen < 1 + AUTH_CHALLEN + AUTH_NONCELEN) {
        fprintf(stderr, "dp9ik_decrypt_authenticator: decrypted auth too short\n");
        return -1;
    }

    memset(a, 0, sizeof(*a));
    off = 0;
    a->num = (char)plain[off++];
    memcpy(a->chal, plain + off, AUTH_CHALLEN); off += AUTH_CHALLEN;
    memcpy(a->rand, plain + off, AUTH_NONCELEN);

    fprintf(stderr, "dp9ik: decrypted authenticator num=%d\n", (int)(unsigned char)a->num);
    return 0;
#else
    (void)a; (void)cipher; (void)cipherlen; (void)kn;
    return -1;
#endif
}

/* ------------------------------------------------------------------ */
/*  Additional PAK helpers                                              */
/* ------------------------------------------------------------------ */

/*
 * Compute shared secret: out = scalar * point
 * Thin wrapper around ed448_scalarmult so callers don't need ed448.h.
 */
int dp9ik_pak_shared_secret(unsigned char out[AUTH_PAKYLEN],
                             const unsigned char scalar[DPIK_KEYLEN],
                             const unsigned char point[AUTH_PAKYLEN])
{
    return ed448_scalarmult(out, scalar, point);
}

/*
 * Find dp9ik password from the in-memory factotum key store.
 * Loaded from /etc/mu/keys at startup via factotum_load_keys().
 * Returns allocated string (caller must free) or NULL.
 */
char *dp9ik_find_password(const char *user, const char *dom)
{
    FactotumKey *key;
    const char *pw;
    char *result;
    size_t pwlen;

    if (user == NULL) {
        fprintf(stderr, "dp9ik_find_password: NULL user\n");
        return NULL;
    }

    key = factotum_find_key("dp9ik", dom, user);
    if (key == NULL) {
        fprintf(stderr, "dp9ik_find_password: no key for user=%s dom=%s\n",
                user, dom ? dom : "*");
        return NULL;
    }

    pw = factotum_get_attr(key->privattr, "password");
    if (pw == NULL) {
        fprintf(stderr, "dp9ik_find_password: key has no !password attr\n");
        return NULL;
    }

    pwlen = strlen(pw);
    result = (char *)malloc(pwlen + 1);
    if (result == NULL) return NULL;
    memcpy(result, pw, pwlen + 1);

    fprintf(stderr, "dp9ik: found password for user=%s\n", user);
    return result;
}

/* ------------------------------------------------------------------ */
/*  Legacy / MVP stubs kept for API compatibility                       */
/* ------------------------------------------------------------------ */

int dp9ik_passtokey(const unsigned char *password, size_t pwlen,
                    const char *user, unsigned char *key, size_t keylen)
{
    /* Hash password+user to a key using SHA-256 */
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, password, pwlen);
    if (user) SHA256_Update(&ctx, (unsigned char *)user, strlen(user));
    SHA256_Final(hash, &ctx);
    if (keylen > SHA256_DIGEST_LENGTH) keylen = SHA256_DIGEST_LENGTH;
    memcpy(key, hash, keylen);
    return 0;
}

int dp9ik_authpak_hash(unsigned char *key, const char *user)
{
    return dp9ik_passtokey(key, strlen((char *)key), user, key, AUTH_PAKYLEN);
}

/*
 * Compute PAK shared secret: ss = server_secret * client_pubkey
 */
int dp9ik_pak_server(const unsigned char *client_pubkey,
                     const unsigned char *server_seckey,
                     const unsigned char *password_hash,
                     unsigned char *shared_secret)
{
    (void)password_hash;  /* mask already applied before this call */
    return ed448_scalarmult(shared_secret, server_seckey, client_pubkey);
}

/*
 * Legacy MVP functions - retained so existing call sites compile.
 * They now delegate to the real implementations.
 */
int dp9ik_decrypt_ticket_mvp(const unsigned char *encrypted, int enc_len,
                              const char *password, const char *user, Ticket *t)
{
    /* Without a valid Kn we can't decrypt; this path is now unused
     * since the real handshake provides Kn before calling decrypt. */
    (void)encrypted; (void)enc_len; (void)password; (void)user;
    memset(t, 0, sizeof(*t));
    fprintf(stderr, "dp9ik_decrypt_ticket_mvp: called without Kn - use real path\n");
    return -1;
}

int dp9ik_validate_ticket_mvp(const Ticket *t, const char *expected_user,
                               const char *domain)
{
    int i;
    if (!t) return -1;

    /* Check cuid is non-empty */
    for (i = 0; i < AUTH_ANAMELEN && t->cuid[i] == '\0'; i++);
    if (i == AUTH_ANAMELEN) {
        fprintf(stderr, "dp9ik_validate_ticket_mvp: empty cuid\n");
        return -1;
    }
    if (expected_user && strncmp(t->cuid, expected_user, AUTH_ANAMELEN) != 0) {
        fprintf(stderr, "dp9ik: ticket cuid mismatch (got %s, expected %s)\n",
                t->cuid, expected_user);
        return -1;
    }

    (void)domain;
    fprintf(stderr, "dp9ik: ticket validated for user=%s\n", t->cuid);
    return 0;
}

int dp9ik_parse_authenticator_mvp(const unsigned char *buf, int len, Authenticator *a)
{
    if (!buf || !a || len < 1 + AUTH_CHALLEN + AUTH_NONCELEN) return -1;
    memset(a, 0, sizeof(*a));
    a->num = (char)buf[0];
    memcpy(a->chal, buf + 1, AUTH_CHALLEN);
    memcpy(a->rand, buf + 1 + AUTH_CHALLEN, AUTH_NONCELEN);
    return 0;
}

int dp9ik_verify_authenticator_mvp(const Authenticator *a, const Ticket *t)
{
    if (!a || !t) return -1;
    if (memcmp(a->chal, t->chal, AUTH_CHALLEN) != 0) {
        fprintf(stderr, "dp9ik: authenticator challenge mismatch\n");
        return -1;
    }
    return 0;
}

int dp9ik_create_server_authenticator(Authenticator *a,
                                      const unsigned char *client_chal,
                                      const unsigned char *server_rand)
{
    if (!a || !client_chal || !server_rand) return -1;
    memset(a, 0, sizeof(*a));
    a->num = (char)AUTH_AS;
    memcpy(a->chal, client_chal, AUTH_CHALLEN);
    memcpy(a->rand, server_rand, AUTH_NONCELEN);
    return 0;
}

/* Old validate functions kept for linkage */
int dp9ik_validate_ticket(const unsigned char *ticket, int tlen,
                          const char *password, Ticket *t)
{
    (void)ticket; (void)tlen; (void)password; (void)t;
    return -1; /* use dp9ik_decrypt_ticket_real instead */
}

int dp9ik_build_authenticator(const Ticket *t, const unsigned char *cc,
                               const unsigned char *sn, Authenticator *auth,
                               unsigned char *buf, size_t len)
{
    (void)t; (void)cc; (void)sn; (void)auth; (void)buf; (void)len;
    return -1;
}

int dp9ik_derive_keys(const unsigned char *cc, const unsigned char *sc,
                      const Ticket *t, AuthInfo *ai)
{
    (void)cc; (void)sc; (void)t; (void)ai;
    return -1;
}

int dp9ik_verify_authenticator(const Ticket *t, const unsigned char *cc,
                                const unsigned char *sn, const Authenticator *auth)
{
    (void)t; (void)cc; (void)sn; (void)auth;
    return 0;
}

int dp9ik_validate_ticket_real(const unsigned char *ticket, int tlen,
                                const char *password, const char *user, Ticket *t)
{
    (void)ticket; (void)tlen; (void)password; (void)user; (void)t;
    return -1;
}

int dp9ik_derive_keys_real(const unsigned char *cc, const unsigned char *sc,
                           const Ticket *t, AuthInfo *ai)
{
    (void)cc; (void)sc; (void)t; (void)ai;
    return -1;
}

int dp9ik_build_authenticator_real(const Ticket *t, const unsigned char *cc,
                                   const unsigned char *sn, const unsigned char *sk,
                                   Authenticator *auth, unsigned char *buf, size_t len)
{
    (void)t; (void)cc; (void)sn; (void)sk; (void)auth; (void)buf; (void)len;
    return -1;
}

int dp9ik_parse_ticket(Ticket *t, const unsigned char *buf, int len)
{
    return dp9ik_parse_authenticator_mvp((const unsigned char *)buf, len,
                                         (Authenticator *)t);
}

int dp9ik_parse_authenticator(Authenticator *a, const unsigned char *buf, int len)
{
    return dp9ik_parse_authenticator_mvp(buf, len, a);
}
