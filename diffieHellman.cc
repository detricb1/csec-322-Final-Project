/* diffieHellman.cc
 *
 * Simplified Diffie-Hellman Key Exchange Implementation
 * 
 * WHAT IS DIFFIE-HELLMAN?
 * -----------------------
 * Imagine you and a friend want to create a shared secret password, but you're
 * talking on a phone that might be tapped. Diffie-Hellman lets you both agree
 * on the SAME secret number without anyone listening being able to figure it out.
 *
 * THE MAGIC:
 * ---------
 * 1. You both agree on two public numbers (P and G) - everyone can know these
 * 2. You pick a secret random number (your private key) - keep this hidden!
 * 3. You do math with your secret and the public numbers → this is your public key
 * 4. You exchange public keys (safe to send over the network)
 * 5. You do math with their public key and your private key → shared secret!
 * 6. They do the same math → SAME shared secret!
 * 7. An eavesdropper can't figure out the shared secret from the public keys
 *
 * EXAMPLE:
 * -------
 * Alice's private: 123        Bob's private: 456
 * Alice's public:  [math]     Bob's public:  [math]
 *         ↓ exchange ↓                ↓ exchange ↓
 * Alice computes: shared = 789        Bob computes: shared = 789
 * 
 * They both get 789, but someone listening only sees the public keys!
 */

#include "diffieHellman.h"
#include <stdlib.h>

/* Fast modular exponentiation: computes (base^exp) % mod efficiently
 * 
 * This is the core math operation for Diffie-Hellman.
 * We can't just compute base^exp directly because the numbers get HUGE.
 * This algorithm computes the result while keeping numbers small using modulo.
 */
unsigned long long modular_pow(unsigned long long base, 
                               unsigned long long exp, 
                               unsigned long long mod)
{
    unsigned long long result = 1;
    base = base % mod;  /* Handle case where base >= mod */
    
    while (exp > 0) {
        /* If exp is odd, multiply base with result */
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        
        /* Now exp must be even, so divide it by 2 */
        exp = exp / 2;
        base = (base * base) % mod;
    }
    
    return result;
}


/* STEP 1: Generate your secret private key
 * 
 * This is YOUR secret number that you never share with anyone.
 * It's just a random number between 1 and a very large number.
 * 
 * Think of it like: picking a secret number between 1 and a billion.
 */
unsigned long long dh_generate_private()
{
    /* Generate a random private key */
    /* We use two rand() calls to get a bigger random number */
    unsigned long long priv = ((unsigned long long)rand() << 32) | rand();
    
    /* Make sure it's in a reasonable range (1 to DH_P-1) */
    priv = (priv % (DH_P - 1)) + 1;
    
    return priv;
}


/* STEP 2: Calculate your public key to send to the other person
 * 
 * This is safe to send over the network because even if someone sees it,
 * they can't figure out your private key from it.
 * 
 * Formula: public_key = (G^private_key) % P
 * 
 * Where:
 *   G = 5 (our agreed-upon generator)
 *   P = 2147483647 (our agreed-upon prime number)
 *   private_key = your secret number from step 1
 */
unsigned long long dh_compute_public(unsigned long long priv)
{
    /* Compute: (G^priv) % P */
    return modular_pow(DH_G, priv, DH_P);
}


/* STEP 3: Calculate the shared secret using the other person's public key
 * 
 * This is the magic step! You use:
 *   - Their PUBLIC key (that they sent you)
 *   - Your PRIVATE key (that you never shared)
 * 
 * And you get the SAME shared secret that they get when they do:
 *   - Your PUBLIC key
 *   - Their PRIVATE key
 * 
 * Formula: shared_secret = (their_public^your_private) % P
 * 
 * THE MAGIC: Both people end up with the same number!
 *   Alice: (Bob's_public^Alice's_private) % P = SHARED_SECRET
 *   Bob:   (Alice's_public^Bob's_private) % P = SAME SHARED_SECRET
 */
unsigned long long dh_compute_shared(unsigned long long other_pub, 
                                     unsigned long long priv)
{
    /* Compute: (other_pub^priv) % P */
    return modular_pow(other_pub, priv, DH_P);
}


/* 
 * PUTTING IT ALL TOGETHER - Example Usage:
 * ----------------------------------------
 * 
 * CLIENT SIDE:
 * -----------
 * 1. unsigned long long my_private = dh_generate_private();
 * 2. unsigned long long my_public = dh_compute_public(my_private);
 * 3. send(my_public);  // Send to server
 * 4. unsigned long long server_public = recv();  // Get from server
 * 5. unsigned long long shared_key = dh_compute_shared(server_public, my_private);
 * 
 * SERVER SIDE:
 * -----------
 * 1. unsigned long long client_public = recv();  // Get from client
 * 2. unsigned long long my_private = dh_generate_private();
 * 3. unsigned long long my_public = dh_compute_public(my_private);
 * 4. send(my_public);  // Send to client
 * 5. unsigned long long shared_key = dh_compute_shared(client_public, my_private);
 * 
 * NOW: Both client and server have the SAME shared_key!
 * This shared_key is then used with XOR cipher to encrypt messages.
 * 
 * SECURITY NOTE:
 * -------------
 * An eavesdropper sees: my_public and their_public
 * But they CAN'T figure out: shared_key
 * (This is hard because of the mathematical properties of modular exponentiation)
 */
