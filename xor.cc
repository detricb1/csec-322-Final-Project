/* xor.cc
 *
 * XOR Encryption/Decryption - Implementation
 * 
 * This file contains the implementation of the XOR cipher.
 * See xor.h for detailed documentation and usage examples.
 */

#include "xor.h"

/* XOR Cipher Implementation
 * 
 * HOW IT WORKS:
 * ------------
 * 1. The key is an 8-byte number (64 bits)
 * 2. We treat those 8 bytes as individual characters
 * 3. We XOR each character in the message with a byte from the key
 * 4. We cycle through the key bytes if the message is longer than 8 characters
 * 
 * VISUAL EXAMPLE:
 * --------------
 * Key (8 bytes):     [K0][K1][K2][K3][K4][K5][K6][K7]
 * 
 * Message:           [H] [e] [l] [l] [o] [W] [o] [r] [l] [d]
 * 
 * XOR with:          [K0][K1][K2][K3][K4][K5][K6][K7][K0][K1]  ← cycles!
 *                     ↓   ↓   ↓   ↓   ↓   ↓   ↓   ↓   ↓   ↓
 * Result:            [?] [?] [?] [?] [?] [?] [?] [?] [?] [?]   ← encrypted
 * 
 * 
 * WHY XOR WORKS FOR ENCRYPTION:
 * ----------------------------
 * XOR has a special mathematical property:
 *   A XOR B XOR B = A
 * 
 * Proof with actual bits:
 *   Let's say A = 01010101 (letter 'U')
 *   Let's say B = 11001100 (key byte)
 *   
 *   First XOR (encrypt):
 *   01010101  (A - original)
 *   11001100  (B - key)
 *   --------  XOR
 *   10011001  (encrypted)
 *   
 *   Second XOR (decrypt):
 *   10011001  (encrypted)
 *   11001100  (B - same key)
 *   --------  XOR
 *   01010101  (A - back to original!)
 * 
 * So:
 *   'H' XOR K0 = '?'         (encryption)
 *   '?' XOR K0 = 'H'         (decryption)
 * 
 * As long as both sides have the same key, they can encrypt and decrypt!
 */
void xor_buffer(char *buf, size_t len, unsigned long long key)
{
    /* Step 1: Treat the 8-byte key as an array of 8 individual bytes
     * 
     * The key is stored as a single 64-bit number in memory, but we need
     * to use it byte-by-byte. This cast converts the pointer.
     * 
     * Example: If key = 0x0102030405060708, then:
     *   key_bytes[0] = 0x08
     *   key_bytes[1] = 0x07
     *   key_bytes[2] = 0x06
     *   ... and so on (depending on endianness)
     * 
     * Note: We don't care about endianness here because both sides
     * will interpret the key the same way.
     */
    char *key_bytes = (char *)&key;

    /* Step 2: Loop through each character in the message */
    for (size_t i = 0; i < len; i++) {
        
        /* Step 3: XOR the character with one byte of the key
         * 
         * The modulo operation (i % 8) makes us cycle through the 8 key bytes:
         * 
         *   i=0 → use key_bytes[0]
         *   i=1 → use key_bytes[1]
         *   i=2 → use key_bytes[2]
         *   i=3 → use key_bytes[3]
         *   i=4 → use key_bytes[4]
         *   i=5 → use key_bytes[5]
         *   i=6 → use key_bytes[6]
         *   i=7 → use key_bytes[7]
         *   i=8 → use key_bytes[0] again (cycling!)
         *   i=9 → use key_bytes[1] again
         *   ... and so on
         * 
         * The ^ operator is the XOR operator in C/C++
         * 
         * This line does:
         *   buf[i] = buf[i] XOR key_bytes[i % 8]
         * 
         * Example for i=0:
         *   If buf[0] = 'H' (72 in ASCII) = 01001000 in binary
         *   If key_bytes[0] = 200 = 11001000 in binary
         *   
         *   01001000  (H)
         *   11001000  (key byte)
         *   --------  XOR
         *   10000000  (128 - encrypted character)
         *   
         *   buf[0] is now 128 (looks like gibberish)
         */
        buf[i] = buf[i] ^ key_bytes[i % 8];
    }
    
    /* That's it! The buffer has been encrypted (or decrypted if it was
     * already encrypted). The operation is symmetric - it works both ways.
     */
}


/*
 * COMPLETE EXAMPLE: Full Encryption Flow
 * ======================================
 * 
 * SENDER SIDE:
 * -----------
 * char message[] = "Secret meeting at noon";
 * unsigned long long shared_key = 987654321;  // From Diffie-Hellman
 * 
 * printf("Original: %s\n", message);
 * // Output: "Secret meeting at noon"
 * 
 * xor_buffer(message, strlen(message), shared_key);
 * // message is now encrypted gibberish
 * 
 * printf("Encrypted: %s\n", message);
 * // Output: something like "ë¢Ã¸Â¡â€šÂ¬â€¹Â¢â€šÂ¬..." (unprintable characters)
 * 
 * send(message);  // Send over network
 * 
 * 
 * RECEIVER SIDE:
 * -------------
 * char received[100];
 * recv(received);  // Receive from network
 * // received contains the encrypted gibberish
 * 
 * unsigned long long shared_key = 987654321;  // Same key from Diffie-Hellman
 * 
 * printf("Received (encrypted): %s\n", received);
 * // Output: "ë¢Ã¸Â¡â€šÂ¬â€¹Â¢â€šÂ¬..." (unprintable characters)
 * 
 * xor_buffer(received, strlen(received), shared_key);
 * // received is now decrypted
 * 
 * printf("Decrypted: %s\n", received);
 * // Output: "Secret meeting at noon" - success!
 * 
 * 
 * WHAT AN EAVESDROPPER SEES:
 * -------------------------
 * They can capture the network traffic, but they only see:
 * - Encrypted gibberish: "ë¢Ã¸Â¡â€šÂ¬â€¹Â¢â€šÂ¬..."
 * 
 * They CANNOT see:
 * - The original message: "Secret meeting at noon"
 * - The shared key: 987654321
 * 
 * Without the key, the encrypted message is useless to them!
 * 
 * 
 * MATHEMATICAL PROOF IT WORKS:
 * ---------------------------
 * Let M = original message byte
 * Let K = key byte
 * Let E = encrypted byte
 * Let D = decrypted byte
 * 
 * Encryption: E = M XOR K
 * Decryption: D = E XOR K = (M XOR K) XOR K = M XOR (K XOR K) = M XOR 0 = M
 * 
 * Since (K XOR K) always equals 0, and (M XOR 0) always equals M,
 * we always get back our original message!
 * 
 * 
 * PERFORMANCE:
 * -----------
 * XOR is VERY fast because:
 * - It's a single CPU instruction per byte
 * - No complex math or lookups required
 * - Works directly on the data in place (no extra memory needed)
 * 
 * This makes it perfect for real-time communication where speed matters.
 * 
 * 
 * LIMITATIONS:
 * -----------
 * 1. Key reuse: Using the same key for many messages can be dangerous
 *    - Solution: Generate a new key for each connection (we do this!)
 * 
 * 2. Known plaintext attacks: If attacker knows part of the message,
 *    they can figure out part of the key
 *    - Solution: Keep messages unpredictable and use strong keys
 * 
 * 3. Not authenticated: Attacker could modify encrypted data
 *    - Solution: Add HMAC or other authentication (advanced topic)
 * 
 * Despite these limitations, XOR cipher with Diffie-Hellman provides
 * good security for educational purposes and moderate-security applications.
 */
