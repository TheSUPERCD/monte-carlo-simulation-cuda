#pragma once
#ifndef SHA3_CPU_H
#define SHA3_CPU_H

#include<stdint.h>
#include<stddef.h>

// state context
typedef struct{
    union{
        uint8_t b[200];
        uint64_t q[25];
    } state;
    int pt, rsiz, digest_size;
} sha3_ctx_t;

// Compression function - To update the state with a specific number of rounds
void keccakf(uint64_t *state);

// Initialize the context for SHA3 - digest_len is the the hash length in bytes
int SHA3_init(sha3_ctx_t *c, int digest_len);

// update state with more data
int SHA3_update(sha3_ctx_t *c, const void *data, size_t len);

// finalize and output a hash - digest goes to md
int SHA3_final(void *md, sha3_ctx_t *c);

// A function to specifically target 16 byte data-types (i.e. 128-bit UUID values) and hash them in one go
void SHA3_16B_cpu(void *digest, const void *bytearr, const int digest_size, const int object_size, size_t num_objects);

void SHA3_16B_validation_v1(void *digest, const void *bytearr, const int digest_size, const int object_size, size_t num_objects);


#endif
