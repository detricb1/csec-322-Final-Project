#ifndef _XOR_H
#define _XOR_H

#include <stddef.h>

/*
 * Encrypts/Decrypts the buffer in place using the key.
 * Running this once Encrypts.
 * Running it again on the same buffer Decrypts.
 */
void xor_buffer(char *buf, size_t len, unsigned long long key);

#endif
