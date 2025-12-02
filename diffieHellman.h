// Diffie-Hellman Header File

#ifndef DIFFIEHELLMAN_H
#define DIFFIEHELLMAN_H

#include <stdint.h>

#define DH_P 2147483647ULL
#define DH_G 5ULL

unsigned long long dh_generate_private();
unsigned long long dh_compute_public(unsigned long long priv);
unsigned long long dh_compute_shared(unsigned long long other_pub, unsigned long long priv);

#endif