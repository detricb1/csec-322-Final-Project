// Diffie-Hellman.cc

#include "diffieHellman.h"
#include <stdlib.h>
#include <time.h>

static unsigned long long modexp(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    __uint128_t result = 1;
    __uint128_t b = base % mod;

    while (exp > 0) {
        if (exp & 1) result = (result * b) % mod;
        b = (b * b) % mod;
        exp >>= 1;
    }
    return (unsigned long long)result;
}

unsigned long long dh_generate_private() {
    unsigned long long r =
        ((unsigned long long)rand() << 32) ^
        rand() ^
        (unsigned long long)time(NULL);

    r &= 0xFFFFFFFFULL;
    if (r == 0) r = 1;
    return r;
}

unsigned long long dh_compute_public(unsigned long long priv) {
    return modexp(DH_G, priv, DH_P);
}

unsigned long long dh_compute_shared(unsigned long long other_pub, unsigned long long priv) {
    return modexp(other_pub, priv, DH_P);
}