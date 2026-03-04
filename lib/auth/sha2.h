/*
 * SHA-256/512 Compatibility Header
 * Provides portable interface for both OpenSSL and pure C implementations
 */

#ifndef SHA2_H
#define SHA2_H

#include <stdint.h>

#ifdef USE_OPENSSL
#include <openssl/sha.h>
#else

/* Pure C SHA-256/512 implementation */

#define SHA256_DIGEST_LENGTH 32
#define SHA256_BLOCK_SIZE 64

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[SHA256_BLOCK_SIZE];
} SHA256_CTX;

#define SHA512_DIGEST_LENGTH 64
#define SHA512_BLOCK_SIZE 128

typedef struct {
    uint64_t state[8];
    uint64_t bitlen[2];
    uint8_t buffer[SHA512_BLOCK_SIZE];
} SHA512_CTX;

/* SHA-256 functions */
void SHA256_Init(SHA256_CTX *ctx);
void SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void SHA256_Final(uint8_t digest[SHA256_DIGEST_LENGTH], SHA256_CTX *ctx);

/* SHA-512 functions */
void SHA512_Init(SHA512_CTX *ctx);
void SHA512_Update(SHA512_CTX *ctx, const uint8_t *data, size_t len);
void SHA512_Final(uint8_t digest[SHA512_DIGEST_LENGTH], SHA512_CTX *ctx);

#endif /* USE_OPENSSL */

#endif /* SHA2_H */
