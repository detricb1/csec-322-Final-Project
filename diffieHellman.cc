#include "diffieHellman.h"
#include <stdlib.h> // for rand()

/*
 * modexp
 * Calculates (base ^ exp) % mod
 * * Why do we need this? 
 * If we calculate 5^100, the number is too big for the computer.
 * This function does the math step-by-step, taking the remainder (%)
 * at every step to keep the number small.
 */
static unsigned long long modexp(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned __int128 result = 1;      // Use 128-bit to prevent overflow during multiply
    unsigned __int128 b = base % mod;

    while (exp > 0) {
        if (exp % 2 == 1) {            // If exponent is odd
            result = (result * b) % mod;
        }
        b = (b * b) % mod;             // Square the base
        exp = exp / 2;                 // Divide exponent by 2
    }
    return (unsigned long long)result;
}

/* * Generate a private key 
 * Just a random number.
 */
unsigned long long dh_generate_private() {
    // Simple random number. We multiply two rands to get a bigger number.
    unsigned long long secret = (unsigned long long)rand() * rand();
    
    // Safety check: Key cannot be 0
    if (secret == 0) secret = 12345; 
    
    return secret;
}

/*
 * Calculate My Public Key (To send to other person)
 * Math: (5 ^ Secret) % P
 */
unsigned long long dh_compute_public(unsigned long long priv) {
    return modexp(DH_G, priv, DH_P);
}

/*
 * Calculate Shared Secret (The final password)
 * Math: (TheirPublic ^ MySecret) % P
 */
unsigned long long dh_compute_shared(unsigned long long other_pub, unsigned long long priv) {
    return modexp(other_pub, priv, DH_P);
}
