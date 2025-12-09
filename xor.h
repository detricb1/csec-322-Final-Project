/* xor.h
 *
 * XOR Encryption/Decryption - Header File
 * 
 * WHAT IS XOR?
 * -----------
 * XOR (exclusive OR) is a simple mathematical operation that's PERFECT for encryption
 * because it has a special property: doing it twice brings you back to the original!
 * 
 * Think of it like a light switch:
 *   - Start with light OFF
 *   - Flip switch once → light ON
 *   - Flip switch again → light OFF (back to original!)
 * 
 * ENCRYPTION vs DECRYPTION:
 * ------------------------
 * With XOR, encryption and decryption are THE SAME OPERATION!
 * 
 *   Original message:  "Hello"
 *   XOR with key:      "nj49f"  ← encrypted (looks like gibberish)
 *   XOR with key again: "Hello" ← decrypted (back to original!)
 * 
 * This is why we have ONE function that does both!
 * 
 * 
 * USAGE EXAMPLE:
 * -------------
 * // Encrypt a message
 * char msg[] = "Secret message";
 * unsigned long long key = 987654321;  // From Diffie-Hellman
 * xor_buffer(msg, strlen(msg), key);
 * // msg is now encrypted gibberish
 * 
 * // Send encrypted message over network
 * send(msg);
 * 
 * // Decrypt the message (same function!)
 * xor_buffer(msg, strlen(msg), key);
 * // msg is "Secret message" again!
 */

#ifndef _XOR_H
#define _XOR_H

#include <stddef.h>

/* XOR Encryption/Decryption Function
 * 
 * This function does BOTH encryption and decryption:
 *   - Call it once on plain text → get encrypted text
 *   - Call it again on encrypted text → get plain text back
 * 
 * Parameters:
 *   buf: The text buffer to encrypt/decrypt (modified in place)
 *   len: The length of the buffer in bytes
 *   key: The shared secret number (typically from Diffie-Hellman)
 * 
 * How it works:
 *   1. Treats the 8-byte key as an array of 8 individual bytes
 *   2. XORs each character in the buffer with a key byte
 *   3. Cycles through the 8 key bytes if the message is longer
 * 
 * Example:
 *   char message[] = "Hello";
 *   
 *   xor_buffer(message, 5, 12345);  // Encrypt
 *   // message is now: [gibberish]
 *   
 *   xor_buffer(message, 5, 12345);  // Decrypt
 *   // message is now: "Hello" (back to original!)
 * 
 * IMPORTANT NOTES:
 * - The buffer is modified IN PLACE (original data is overwritten)
 * - Both sender and receiver must use the SAME key
 * - The same function encrypts and decrypts
 * - Security depends on keeping the key secret
 * 
 * Visual Example:
 *   Message:  [H] [e] [l] [l] [o]
 *   Key:      [K0][K1][K2][K3][K4]
 *   XOR (^):   ↓   ↓   ↓   ↓   ↓
 *   Result:   [?] [?] [?] [?] [?]  ← Encrypted
 *   
 *   XOR again with same key:
 *   Result:   [H] [e] [l] [l] [o]  ← Back to original!
 */
void xor_buffer(char *buf, size_t len, unsigned long long key);

#endif


/*
 * RELATIONSHIP WITH DIFFIE-HELLMAN:
 * =================================
 * 
 * Diffie-Hellman provides the KEY
 * XOR uses that KEY to encrypt/decrypt
 * 
 * Complete workflow:
 * -----------------
 * 
 * 1. SETUP PHASE (once per connection):
 *    - Use Diffie-Hellman to get a shared key
 *    - Both client and server now have the same secret number
 * 
 * 2. MESSAGING PHASE (every message):
 *    - Sender: xor_buffer(message, len, shared_key)  → encrypt
 *    - Send encrypted message over network
 *    - Receiver: xor_buffer(message, len, shared_key)  → decrypt
 * 
 * Example:
 * -------
 * // After Diffie-Hellman, both sides have:
 * unsigned long long shared_key = 123456789;
 * 
 * // Client encrypts and sends:
 * char msg[] = "Post note: Meeting at 3pm";
 * xor_buffer(msg, strlen(msg), shared_key);
 * send(msg);  // Sends encrypted gibberish
 * 
 * // Server receives and decrypts:
 * char received[256];
 * recv(received);  // Receives encrypted gibberish
 * xor_buffer(received, strlen(received), shared_key);
 * // received is now "Post note: Meeting at 3pm"
 * 
 * 
 * WHY IS THIS SECURE?
 * ------------------
 * - The key was created using Diffie-Hellman (secure key exchange)
 * - Only the two parties know the key
 * - An eavesdropper only sees encrypted gibberish
 * - Without the key, decryption is extremely difficult
 * 
 * 
 * SECURITY LEVEL:
 * --------------
 * XOR cipher with a one-time key is theoretically unbreakable!
 * However, we reuse our key multiple times, which reduces security.
 * 
 * This is good for:
 * ✓ Learning encryption concepts
 * ✓ Moderate security needs
 * ✓ Fast encryption/decryption
 * 
 * Not recommended for:
 * ✗ Banking or financial data
 * ✗ Medical records
 * ✗ Government/military use
 * 
 * For high security, use AES, ChaCha20, or other modern ciphers.
 */
