/*
 * Pure C SHA-256 and SHA-512 Implementation
 * For Plan 9 compiler compatibility
 *
 * This implementation follows the FIPS 180-4 standard
 * and is designed to be portable and C89 compliant.
 *
 * Based on public domain implementations by Brad Conte
 * and various RFC references.
 */

#ifndef USE_OPENSSL

#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* SHA-256 Implementation                                               */
/* ------------------------------------------------------------------ */

#define SHA256_DIGEST_LENGTH 32
#define SHA256_BLOCK_SIZE 64

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[SHA256_BLOCK_SIZE];
} SHA256_CTX;

static const uint32_t k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ae, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t buffer[SHA256_BLOCK_SIZE])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)buffer[i * 4]) << 24 |
               ((uint32_t)buffer[i * 4 + 1]) << 16 |
               ((uint32_t)buffer[i * 4 + 2]) << 8 |
               ((uint32_t)buffer[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    /* Compression loop */
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + k256[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Update state */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void SHA256_Init(SHA256_CTX *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->bitlen = 0;
    memset(ctx->buffer, 0, SHA256_BLOCK_SIZE);
}

void SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        ctx->buffer[ctx->bitlen % 64] = data[i];
        ctx->bitlen++;
        if (ctx->bitlen % 64 == 0) {
            sha256_transform(ctx, ctx->buffer);
        }
    }
}

void SHA256_Final(uint8_t digest[SHA256_DIGEST_LENGTH], SHA256_CTX *ctx)
{
    uint64_t i = ctx->bitlen;
    int j;

    /* Pad the message */
    ctx->buffer[i % 64] = 0x80;
    i++;

    if ((i % 64) > 56) {
        while (i % 64 != 0) {
            ctx->buffer[i % 64] = 0;
            i++;
        }
        sha256_transform(ctx, ctx->buffer);
        i = 0;
    }

    while (i < 56) {
        ctx->buffer[i % 64] = 0;
        i++;
    }

    /* Append length in bits */
    ctx->bitlen *= 8;
    for (j = 0; j < 8; j++) {
        ctx->buffer[56 + j] = (ctx->bitlen >> (56 - j * 8)) & 0xff;
    }

    sha256_transform(ctx, ctx->buffer);

    /* Output digest */
    for (i = 0; i < 4; i++) {
        digest[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        digest[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        digest[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        digest[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        digest[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        digest[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        digest[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        digest[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

/* ------------------------------------------------------------------ */
/* SHA-512 Implementation                                               */
/* ------------------------------------------------------------------ */

#define SHA512_DIGEST_LENGTH 64
#define SHA512_BLOCK_SIZE 128

typedef struct {
    uint64_t state[8];
    uint64_t bitlen[2];
    uint8_t buffer[SHA512_BLOCK_SIZE];
} SHA512_CTX;

static const uint64_t k512[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ae5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

#define ROTRIGHT64(a,b) (((a) >> (b)) | ((a) << (64-(b))))
#define CH64(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP064(x) (ROTRIGHT64(x,28) ^ ROTRIGHT64(x,34) ^ ROTRIGHT64(x,39))
#define EP164(x) (ROTRIGHT64(x,14) ^ ROTRIGHT64(x,18) ^ ROTRIGHT64(x,41))
#define SIG064(x) (ROTRIGHT64(x,1) ^ ROTRIGHT64(x,8) ^ ((x) >> 7))
#define SIG164(x) (ROTRIGHT64(x,19) ^ ROTRIGHT64(x,61) ^ ((x) >> 6))

static void sha512_transform(SHA512_CTX *ctx, const uint8_t buffer[SHA512_BLOCK_SIZE])
{
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t1, t2;
    int i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint64_t)buffer[i * 8]) << 56 |
               ((uint64_t)buffer[i * 8 + 1]) << 48 |
               ((uint64_t)buffer[i * 8 + 2]) << 40 |
               ((uint64_t)buffer[i * 8 + 3]) << 32 |
               ((uint64_t)buffer[i * 8 + 4]) << 24 |
               ((uint64_t)buffer[i * 8 + 5]) << 16 |
               ((uint64_t)buffer[i * 8 + 6]) << 8 |
               ((uint64_t)buffer[i * 8 + 7]);
    }
    for (i = 16; i < 80; i++) {
        w[i] = SIG164(w[i - 2]) + w[i - 7] + SIG064(w[i - 15]) + w[i - 16];
    }

    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    /* Compression loop */
    for (i = 0; i < 80; i++) {
        t1 = h + EP164(e) + CH64(e, f, g) + k512[i] + w[i];
        t2 = EP064(a) + MAJ64(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Update state */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void SHA512_Init(SHA512_CTX *ctx)
{
    ctx->state[0] = 0x6a09e667f3bcc908;
    ctx->state[1] = 0xbb67ae8584caa73b;
    ctx->state[2] = 0x3c6ef372fe94f82b;
    ctx->state[3] = 0xa54ff53a5f1d36f1;
    ctx->state[4] = 0x510e527fade682d1;
    ctx->state[5] = 0x9b05688c2b3e6c1f;
    ctx->state[6] = 0x1f83d9abfb41bd6b;
    ctx->state[7] = 0x5be0cd19137e2179;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;
    memset(ctx->buffer, 0, SHA512_BLOCK_SIZE);
}

void SHA512_Update(SHA512_CTX *ctx, const uint8_t *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        ctx->buffer[ctx->bitlen[0] % 128] = data[i];
        ctx->bitlen[0]++;
        if (ctx->bitlen[0] % 128 == 0) {
            if (ctx->bitlen[0] == 0) ctx->bitlen[1]++;
            sha512_transform(ctx, ctx->buffer);
        }
    }
}

void SHA512_Final(uint8_t digest[SHA512_DIGEST_LENGTH], SHA512_CTX *ctx)
{
    uint64_t i = ctx->bitlen[0];
    int j;

    /* Pad the message */
    ctx->buffer[i % 128] = 0x80;
    i++;

    if ((i % 128) > 112) {
        while (i % 128 != 0) {
            ctx->buffer[i % 128] = 0;
            i++;
        }
        sha512_transform(ctx, ctx->buffer);
        i = 0;
    }

    while (i < 112) {
        ctx->buffer[i % 128] = 0;
        i++;
    }

    /* Append length in bits */
    ctx->bitlen[0] *= 8;
    for (j = 0; j < 8; j++) {
        ctx->buffer[112 + j] = (ctx->bitlen[0] >> (56 - j * 8)) & 0xff;
    }
    for (j = 0; j < 8; j++) {
        ctx->buffer[120 + j] = (ctx->bitlen[1] >> (56 - j * 8)) & 0xff;
    }

    sha512_transform(ctx, ctx->buffer);

    /* Output digest */
    for (i = 0; i < 8; i++) {
        digest[i]      = (ctx->state[0] >> (56 - i * 8)) & 0xff;
        digest[i + 8]  = (ctx->state[1] >> (56 - i * 8)) & 0xff;
        digest[i + 16] = (ctx->state[2] >> (56 - i * 8)) & 0xff;
        digest[i + 24] = (ctx->state[3] >> (56 - i * 8)) & 0xff;
        digest[i + 32] = (ctx->state[4] >> (56 - i * 8)) & 0xff;
        digest[i + 40] = (ctx->state[5] >> (56 - i * 8)) & 0xff;
        digest[i + 48] = (ctx->state[6] >> (56 - i * 8)) & 0xff;
        digest[i + 56] = (ctx->state[7] >> (56 - i * 8)) & 0xff;
    }
}

#endif /* USE_OPENSSL */
