/*
 * xor.cc
 * Simplified Encryption
 */

#include "xor.h"
#include <stdio.h> // For NULL

/*
 * This function takes a message (buf) and a secret key.
 * It goes through the message byte-by-byte and "XORs" it with the key.
 * * We treat the 8-byte (long long) key as an array of 8 characters.
 * We repeat this 8-byte pattern over the entire message.
 */
void xor_buffer(char *buf, size_t len, unsigned long long key) {
    // 1. View the 8-byte integer key as an array of 8 bytes
    char *key_bytes = (char *)&key;

    // 2. Loop through the message buffer
    for (size_t i = 0; i < len; i++) {
        // 3. XOR the current character with the corresponding byte of the key.
        //    (i % 8) ensures we cycle 0-7, 0-7, 0-7...
        buf[i] = buf[i] ^ key_bytes[i % 8];
    }
}
