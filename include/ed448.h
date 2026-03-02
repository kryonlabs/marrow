/*
 * Ed448-Goldilocks curve operations for dp9ik authentication
 * C89/C90 compliant
 *
 * Implements the SPAKE2-EE Password Authenticated Key Exchange used
 * by 9front's dp9ik authentication protocol.
 *
 * Curve: x² + y² = 1 + d·x²·y² (standard Edwards)
 *   where d = -39081 (mod p), p = 2^448 - 2^224 - 1
 *
 * Point encoding: 57 bytes (RFC 8032 Ed448 style)
 *   bytes 0-55: y-coordinate, little-endian
 *   byte 56, bit 7: sign of x
 *
 * Scalar: 56 bytes, clamped to the group order
 *   Group order: n = 2^446 - 13818066809895115352007386748515426880316871408789605
 */

#ifndef ED448_H
#define ED448_H

#include <stddef.h>
#include <stdint.h>

/*
 * Field element: 448-bit integer, stored as OpenSSL BIGNUM internally.
 * External callers use opaque pointer.
 */

/* Size of encoded point in bytes (Decaf encoding for dp9ik, not standard 57-byte Ed448) */
#define ED448_POINTLEN  56  /* AUTH_PAKYLEN - Decaf-encoded points used by dp9ik */

/* Size of scalar in bytes */
#define ED448_SCALARLEN 56

/*
 * Initialize the Ed448 subsystem. Must be called once before use.
 * Returns 0 on success, -1 on error.
 */
int ed448_init(void);

/*
 * Clean up the Ed448 subsystem. Call on shutdown.
 */
void ed448_cleanup(void);

/*
 * Generate a random scalar suitable for use as a private key.
 * The scalar is clamped per the protocol spec.
 * Returns 0 on success, -1 on error.
 */
int ed448_scalar_generate(unsigned char scalar[ED448_SCALARLEN]);

/*
 * Compute the public key from a private scalar.
 * pub = scalar * G  (G is the base point)
 * Returns 0 on success, -1 on error.
 */
int ed448_scalarmult_base(unsigned char pub[ED448_POINTLEN],
                          const unsigned char scalar[ED448_SCALARLEN]);

/*
 * Compute a Diffie-Hellman shared secret.
 * out = scalar * point
 * Returns 0 on success, -1 on error.
 */
int ed448_scalarmult(unsigned char out[ED448_POINTLEN],
                     const unsigned char scalar[ED448_SCALARLEN],
                     const unsigned char point[ED448_POINTLEN]);

/*
 * Add two encoded points.
 * out = A + B
 * Returns 0 on success, -1 on error (invalid point).
 */
int ed448_point_add(unsigned char out[ED448_POINTLEN],
                    const unsigned char A[ED448_POINTLEN],
                    const unsigned char B[ED448_POINTLEN]);

/*
 * Subtract two encoded points.
 * out = A - B
 * Returns 0 on success, -1 on error (invalid point).
 */
int ed448_point_sub(unsigned char out[ED448_POINTLEN],
                    const unsigned char A[ED448_POINTLEN],
                    const unsigned char B[ED448_POINTLEN]);

/*
 * Hash data to a curve point (for PAK password masking).
 * Uses try-and-increment: hash the seed, interpret as y, solve for x.
 * Returns 0 on success, -1 on error.
 */
int ed448_hash_to_point(unsigned char out[ED448_POINTLEN],
                        const unsigned char *data, size_t len);

/*
 * Check if a 57-byte buffer is a valid encoded Ed448 point.
 * Returns 1 if valid, 0 if not.
 */
int ed448_point_valid(const unsigned char point[ED448_POINTLEN]);

#endif /* ED448_H */
