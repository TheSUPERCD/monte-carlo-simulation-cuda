#pragma once
#ifndef SHA3_GPU_H
#define SHA3_GPU_H

#include<stdint.h>
#include<stddef.h>
#include<cuda_runtime.h>

// Compression function - To update the state with a specific number of rounds
__device__ void keccakf(uint64_t *state);

__global__ void SHA3_16B(uint8_t *digest, const uint8_t *bytearr, const int digest_size, const int object_size);

// A function to specifically target 16 byte data-types (i.e. 128-bit UUID values) and hash them in one go
void SHA3_16B_gpu(uint8_t *digest, const uint8_t *bytearr, const int digest_size, const int object_size, size_t num_objects, size_t num_objects_batch);



#endif
