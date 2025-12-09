/* diffieHellman.h
 *
 * Diffie-Hellman Key Exchange - Header File
 * 
 * OVERVIEW:
 * --------
 * This provides functions for securely agreeing on a shared secret key
 * between two parties over an insecure network.
 * 
 * The shared key can then be used for encryption (like with XOR cipher).
 * 
 * USAGE EXAMPLE:
 * -------------
 * // Step 1: Generate your private key (keep secret!)
 * unsigned long long my_private = dh_generate_private();
 * 
 * // Step 2: Calculate your public key (safe to send)
 * unsigned long long my_public = dh_compute_public(my_private);
 * 
 * // Step 3: Exchange public keys with the other party
 * send(my_public);
 * unsigned long long their_public = receive();
 * 
 * // Step 4: Compute the shared secret
 * unsigned long long shared_key = dh_compute_shared(their_public, my_private);
 * 
 * // Now both parties have the same shared_key!
 */

#ifndef _DIFFIEHELLMAN_H
#define _DIFFIEHELLMAN_H

#include <stdint.h>

/* Diffie-Hellman Public Constants
 * 
 * These are the "agreed upon" numbers that everyone can know.
 * Think of them as the rules of the game that both players follow.
 * 
 * DH_P: A large prime number (2^31 - 1 = 2147483647)
 *       This is called the "modulus" - it keeps our numbers from getting too big
 * 
 * DH_G: A generator number (5)
 *       This is the base we use for all our calculations
 * 
 * WHY THESE NUMBERS?
 * - P must be prime for the math to work securely
 * - G must be a "generator" - a special number that works well with P
 * - These are standard values used in real Diffie-Hellman implementations
 */
#define DH_P 2147483647ULL
#define DH_G 5ULL


/* FUNCTION 1: Generate Private Key
 * 
 * Purpose: Creates a random secret number that you never share
 * 
 * Returns: Your private key (a random number)
 * 
 * Example:
 *   unsigned long long my_secret = dh_generate_private();
 *   // my_secret might be something like: 84729361048
 * 
 * IMPORTANT: Never send this over the network! Keep it secret!
 */
unsigned long long dh_generate_private();


/* FUNCTION 2: Compute Public Key
 * 
 * Purpose: Calculates a public key from your private key
 *          This is SAFE to send over the network
 * 
 * Parameters:
 *   priv: Your private key (from dh_generate_private)
 * 
 * Returns: Your public key
 * 
 * Math: public_key = (G^priv) % P
 * 
 * Example:
 *   unsigned long long my_private = dh_generate_private();
 *   unsigned long long my_public = dh_compute_public(my_private);
 *   send_to_other_person(my_public);  // Safe to send!
 * 
 * Why is this safe?
 * - Even if someone sees your public key, they can't figure out your private key
 * - This is because reversing the operation is mathematically very hard
 */
unsigned long long dh_compute_public(unsigned long long priv);


/* FUNCTION 3: Compute Shared Secret
 * 
 * Purpose: Combines the other person's public key with your private key
 *          to create a shared secret that BOTH of you will compute
 * 
 * Parameters:
 *   other_pub: The other person's public key (received from them)
 *   priv:      Your private key (your secret)
 * 
 * Returns: The shared secret key
 * 
 * Math: shared_secret = (other_pub^priv) % P
 * 
 * Example:
 *   // You compute:
 *   unsigned long long shared = dh_compute_shared(their_public, my_private);
 *   
 *   // They compute:
 *   unsigned long long shared = dh_compute_shared(your_public, their_private);
 *   
 *   // Both get the SAME number!
 * 
 * THE MAGIC:
 * You: (their_public ^ your_private) % P = SHARED_SECRET
 * Them: (your_public ^ their_private) % P = SAME SHARED_SECRET
 * 
 * This shared secret can now be used as an encryption key!
 */
unsigned long long dh_compute_shared(unsigned long long other_pub, 
                                     unsigned long long priv);

#endif


/*
 * COMPLETE WORKFLOW DIAGRAM:
 * =========================
 * 
 * ALICE'S SIDE                        BOB'S SIDE
 * ------------                        ----------
 * 
 * 1. priv_A = generate_private()      1. priv_B = generate_private()
 *    (e.g., 123)                         (e.g., 456)
 * 
 * 2. pub_A = compute_public(priv_A)   2. pub_B = compute_public(priv_B)
 *    (e.g., 8888)                        (e.g., 9999)
 * 
 * 3. Send pub_A ────────────→         3. Receive pub_A (8888)
 * 
 * 4. Receive pub_B (9999) ←──────────  4. Send pub_B
 * 
 * 5. shared = compute_shared(         5. shared = compute_shared(
 *       pub_B,    ← from Bob              pub_A,    ← from Alice
 *       priv_A)   ← Alice's secret        priv_B)   ← Bob's secret
 *    = 77777                              = 77777
 * 
 * Result: Both Alice and Bob have 77777 as their shared secret!
 * 
 * An eavesdropper only sees: 8888 and 9999
 * They CANNOT figure out: 77777
 * 
 * 
 * NEXT STEP:
 * ---------
 * Use the shared secret (77777) with xor_buffer() to encrypt messages!
 * 
 * Example:
 *   char msg[] = "Secret message";
 *   xor_buffer(msg, strlen(msg), 77777);  // Encrypted
 *   send(msg);
 *   
 *   // Receiver:
 *   xor_buffer(msg, strlen(msg), 77777);  // Decrypted
 */
