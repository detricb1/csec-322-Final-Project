#include "xor.h"

/*
 * xor_buffer
 * Inputs: 
 * buf: The text to encrypt (e.g., "Hello")
 * len: The length of the text
 * key: The secret shared number
 */
void xor_buffer(char *buf, size_t len, unsigned long long key) {
    // 1. Treat the 8-byte integer key as an array of 8 characters
    char *key_bytes = (char *)&key;

    // 2. Loop through the message character by character
    for (size_t i = 0; i < len; i++) {
        
        // 3. XOR the character with a piece of the key
        // (i % 8) makes us cycle through the key: 0, 1, 2...7, 0, 1...
        buf[i] = buf[i] ^ key_bytes[i % 8];
    }
}
