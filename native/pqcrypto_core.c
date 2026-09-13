#include "pqcrypto_core.h"
#include <string.h>

void qshield_secure_zero(void *v, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) {
        *p++ = 0;
    }
}

int qshield_ct_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (pa[i] ^ pb[i]);
    }
    return (int)diff;
}

void qshield_poly_mul_negacyclic(int16_t *c, const int16_t *a, const int16_t *b) {
    int32_t temp[2 * KYBER_N - 1];
    memset(temp, 0, sizeof(temp));

    for (int i = 0; i < KYBER_N; i++) {
        int32_t ai = a[i];
        for (int j = 0; j < KYBER_N; j++) {
            temp[i + j] = (temp[i + j] + ai * b[j]) % KYBER_Q;
        }
    }

    for (int k = 0; k < KYBER_N - 1; k++) {
        int32_t val = (temp[k] - temp[k + KYBER_N]) % KYBER_Q;
        if (val < 0) val += KYBER_Q;
        c[k] = (int16_t)val;
    }
    int32_t last = temp[KYBER_N - 1] % KYBER_Q;
    if (last < 0) last += KYBER_Q;
    c[KYBER_N - 1] = (int16_t)last;
}
