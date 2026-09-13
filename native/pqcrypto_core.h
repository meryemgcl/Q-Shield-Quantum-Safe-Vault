/**
 * Q-Shield Native Cryptographic Acceleration Layer (C/C++ AVX2 & NEON)
 * NIST FIPS 203 (ML-KEM / CRYSTALS-Kyber) & FIPS 204 (ML-DSA / CRYSTALS-Dilithium)
 * Constant-time arithmetic and memory zeroization.
 */

#ifndef QSHIELD_PQCRYPTO_CORE_H
#define QSHIELD_PQCRYPTO_CORE_H

#include <stdint.h>
#include <stddef.h>

#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_K 3

#ifdef __cplusplus
extern "C" {
#endif

// Constant-time memory zeroization (prevents compiler optimization removal)
void qshield_secure_zero(void *v, size_t n);

// Constant-time comparison
int qshield_ct_memcmp(const void *a, const void *b, size_t n);

// Fast negacyclic polynomial multiplication mod (X^256 + 1, 3329)
void qshield_poly_mul_negacyclic(int16_t *c, const int16_t *a, const int16_t *b);

// Centered Binomial Distribution sampling (eta=2)
void qshield_cbd2(int16_t *poly, const uint8_t *bytes);

#ifdef __cplusplus
}
#endif

#endif // QSHIELD_PQCRYPTO_CORE_H
