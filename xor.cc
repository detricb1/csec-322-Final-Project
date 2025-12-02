// xor.cc

#include "xor.h"

void xor_buffer(char *buf, size_t len, unsigned long long key) {
    unsigned char k = (unsigned char)(key & 0xFF);

    for (size_t i = 0; i < len; i++) {
        buf[i] ^= k;
        k = (unsigned char)((k + 31) & 0xFF);
    }
}