#ifndef DIFFIEHELLMAN_H
#define DIFFIEHELLMAN_H

#include <stdint.h>

/* * Standard Diffie-Hellman Constants 
 * P = A large prime number (2^31 - 1)
 * G = A generator (5)
 */
#define DH_P 2147483647ULL
#define DH_G 5ULL

// Generates your secret private key
unsigned long long dh_generate_private();

// Calculates your public key to send to the other person
unsigned long long dh_compute_public(unsigned long long priv);

// Calculates the final shared secret using the other person's public key
unsigned long long dh_compute_shared(unsigned long long other_pub, unsigned long long priv);

#endif
