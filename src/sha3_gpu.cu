#include<iostream>
#include <sha3_gpu.cuh>


#define THREADBLOCK_SIZE 512


#define KECCAKF_ROUNDS 24
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

// constants
__device__ const uint64_t keccakf_rndc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};
__device__ const uint8_t keccakf_rotc[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};
__device__ const uint8_t keccakf_piln[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

// Compression function - To update the state with a specific number of rounds
__device__ void keccakf(uint64_t *state){
    // variables
    uint64_t temp, intermediate[5];
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    uint8_t *endian_little;

    // Endian conversion. If your machine is little-endian, this part becomes redundant
    #pragma unroll 25
    for(int i=0;i<25;i++){
        endian_little = (uint8_t *) &state[i];
        state[i] = ((uint64_t)  endian_little[0])          |
                (((uint64_t) endian_little[1]) <<  8)   |
                (((uint64_t) endian_little[2]) << 16)   | 
                (((uint64_t) endian_little[3]) << 24)   |
                (((uint64_t) endian_little[4]) << 32)   |
                (((uint64_t) endian_little[5]) << 40)   |
                (((uint64_t) endian_little[6]) << 48)   |
                (((uint64_t) endian_little[7]) << 56);
    }
#endif
    // cryptographic iterations
    #pragma unroll
    for(int r=0;r<KECCAKF_ROUNDS;r++){
        // theta block
        #pragma unroll 5
        for(int i=0;i<5;i++)
            intermediate[i] = state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20];

        #pragma unroll 5
        for (int i=0;i<5;i++){
            temp = intermediate[(i+4)%5] ^ ROTL64(intermediate[(i+1)%5], 1);
            #pragma unroll 5
            for (int j=0;j<25;j+=5)
                state[j+i] ^= temp;
        }

        // combined rho & pi block
        int k;
        temp = state[1];

        #pragma unroll 24
        for(int i=0;i<24;i++){
            k = keccakf_piln[i];
            intermediate[0] = state[k];
            state[k] = ROTL64(temp, keccakf_rotc[i]);
            temp = intermediate[0];
        }

        //  chi block
        #pragma unroll 5
        for (int j=0;j<25;j+=5){
            #pragma unroll 5
            for(int i=0;i<5;i++)
                intermediate[i] = state[j+i];
            
            #pragma unroll 5
            for(int i=0;i<5;i++)
                state[j+i] ^= (~intermediate[(i+1)%5]) & intermediate[(i+2)%5];
        }

        //  iota block
        state[0] ^= keccakf_rndc[r];
    }

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    // Endian conversion - again
    #pragma unroll 25
    for(int i=0;i<25;i++){
        endian_little = (uint8_t *) &state[i];
        temp = state[i];
        endian_little[0] = temp & 0xFF;
        endian_little[1] = (temp >>  8) & 0xFF;
        endian_little[2] = (temp >> 16) & 0xFF;
        endian_little[3] = (temp >> 24) & 0xFF;
        endian_little[4] = (temp >> 32) & 0xFF;
        endian_little[5] = (temp >> 40) & 0xFF;
        endian_little[6] = (temp >> 48) & 0xFF;
        endian_little[7] = (temp >> 56) & 0xFF;
    }
#endif
}


// A function to specifically target 16 byte data-types (i.e. 128-bit UUID values) and hash them in one go
__global__ void SHA3_16B(uint8_t *digest, const uint8_t *bytearr, const int digest_size, const int object_size){
    int gid = blockIdx.x * blockDim.x + threadIdx.x;
    int global_mem_offest_bytearr = gid * object_size;
    int global_mem_offest_digestarr = gid * digest_size;
    int rsiz = 200 - 2 * digest_size;
    
    uint8_t b[200] = {0};
    for(int i=0;i<object_size;i++){
        b[i] = bytearr[global_mem_offest_bytearr + i];
    }
    __syncthreads();
    
    b[object_size] ^= 0x06;
    b[rsiz - 1] ^= 0x80;
    keccakf((uint64_t *)b);
    
    __syncthreads();
    for(int i=0;i<digest_size;i++){
        digest[global_mem_offest_digestarr + i] = b[i];
    }
    
}

void SHA3_16B_gpu(uint8_t *digest, const uint8_t *bytearr, const int digest_size, const int object_size, size_t num_objects, size_t num_objects_batch){
    const size_t bytearr_bytes = num_objects_batch*object_size;
    const size_t digest_bytes = num_objects_batch*digest_size;

    int remaining_objects = (num_objects % THREADBLOCK_SIZE);
    int num_blocks = (int)(num_objects/THREADBLOCK_SIZE) + (remaining_objects ? 1 : 0);
    int num_threads = (num_objects < THREADBLOCK_SIZE) ? remaining_objects : THREADBLOCK_SIZE;

    std::cout<<"num blocks: "<<num_blocks<<" | num threads: "<<num_threads<<"\n";

    uint8_t *device_bytearr;
    uint8_t *device_digest;
    cudaMalloc(&device_bytearr, bytearr_bytes);
    cudaMalloc(&device_digest, digest_bytes);

    cudaMemcpy(device_bytearr, bytearr, bytearr_bytes, cudaMemcpyHostToDevice);

    SHA3_16B<<<num_blocks, num_threads>>>(device_digest, device_bytearr, digest_size, object_size);

    cudaMemcpy(digest, device_digest, digest_bytes, cudaMemcpyDeviceToHost);
    cudaFree(device_bytearr);
    cudaFree(device_digest);
}
