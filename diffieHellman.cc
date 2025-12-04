/*
 * diffieHellman.cc
 * Simplified Key Exchange
 */

#include "diffieHellman.h"
#include <stdlib.h> // For rand()
#include <time.h>   // For time()

/* * Modular Exponentiation
 * Calculates: (base ^ exp) % mod
 * * We cannot just do "base ^ exp" normally because the number would be 
 * too huge for the computer to hold. This function does the math 
 * step-by-step to keep the numbers small (modulo P).
 */
static unsigned long long modexp(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned __int128 result = 1;
    unsigned __int128 b = base % mod;

    while (exp > 0) {
        // If exp is odd, multiply result by b
        if (exp % 2 == 1) {
            result = (result * b) % mod;
        }
        // Square b and divide exp by 2
        b = (b * b) % mod;
        exp = exp / 2;
    }
    return (unsigned long long)result;
}

/*
 * Generate a random private key.
 * Simplified to just use standard random numbers.
 */
unsigned long long dh_generate_private() {
    // Simple random number. 
    // We combine two rand() calls to ensure we get a large enough number
    // since rand() normally only goes up to ~32,000 or ~2 billion.
    unsigned long long r1 = rand();
    unsigned long long r2 = rand();
    
    // Combine them (shift one over by 16 bits)
    unsigned long long private_key = (r1 << 16) | r2;

    // Ensure it's never 0
    if (private_key == 0) private_key = 1;

    return private_key;
}

/*
 * Calculate My Public Key
 * Formula: (G ^ MyPrivateKey) % P
 */
unsigned long long dh_compute_public(unsigned long long priv) {
    return modexp(DH_G, priv, DH_P);
}

/*
 * Calculate Shared Secret
 * Formula: (TheirPublicKey ^ MyPrivateKey) % P
 */
unsigned long long dh_compute_shared(unsigned long long other_pub, unsigned long long priv) {
    return modexp(other_pub, priv, DH_P);
}
