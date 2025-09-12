#include <filesystem>
#include <util_funcs.h>
#include <sha3_gpu.cuh>

#define DIGEST_SIZE 64
#define UUID_SIZE 16
#define NUM_UUID_TO_READ 100*1000*1L
#define NUM_UUIDS_PER_BATCH 512*1000*1L
#define OUTFILE_DIR "../hashed_output/"

// This determines if the hashed results should be compressed or not, before saving to disk
#define COMPRESS_HASHES 1


int main(int argc, char** argv){
    std::string filename;
    if(argc>1) filename = argv[1];
    else ERROR("\nERROR: No filename provided!")

    const size_t num_uuids_to_read = NUM_UUID_TO_READ;
    const size_t num_uuid_per_batch = NUM_UUIDS_PER_BATCH;
    
    const size_t uuid_batch_size_in_bytes = num_uuid_per_batch * UUID_SIZE;
    const size_t digest_size_in_bytes = num_uuid_per_batch * DIGEST_SIZE;
    const size_t num_bytes_to_read = ((UUID_SIZE*2 + 1)*num_uuids_to_read - 1);
    
    int last_dot = filename.find_last_of(".");
    int last_dir = filename.find_last_of("/")+1;
    std::string outfile_name = OUTFILE_DIR + filename.substr(last_dir, last_dot-last_dir) + "_hashed_byGPU";
    if(COMPRESS_HASHES) outfile_name += ".bin";
    else outfile_name += ".txt";
    if(!std::filesystem::exists(OUTFILE_DIR)){
        if(!std::filesystem::create_directories(OUTFILE_DIR)){
          std::cerr<<"Unable to create directories!"<<std::endl;
          return 1;
        }
    }

    FILE *input_fp = createFilePointer(argv[1]);
    FILE *output_fp = std::fopen(outfile_name.c_str(), "wb+");

    uint8_t *buf = (uint8_t *)malloc(uuid_batch_size_in_bytes);
    uint8_t *output_digest = (uint8_t *)malloc(digest_size_in_bytes);
    // uint8_t *validation_digest = (uint8_t *)malloc(digest_size_in_bytes);
    
    int uuid_char_length = (UUID_SIZE*2 + 1);
    size_t total_raw_bytes_to_batch_read = uuid_char_length*num_uuid_per_batch;
    uint8_t *uuid_raw_vals = (uint8_t *)malloc(total_raw_bytes_to_batch_read);

    int current_batch_num = 0;
    std::size_t total_bytes_read = 0;
    while(true){
        std::cout << "Current batch: " << ++current_batch_num;
        size_t num_uuid_read = getUUID_bytes(input_fp, buf, uuid_raw_vals, UUID_SIZE, total_raw_bytes_to_batch_read, &total_bytes_read);
        std::cout << " | UUIDs read: " << num_uuid_read << std::endl;
        
        uint8_t eof_flag = (total_bytes_read >= num_bytes_to_read) || feof(input_fp);
        
        SHA3_16B_gpu(output_digest, buf, DIGEST_SIZE, UUID_SIZE, num_uuid_read, num_uuid_per_batch);
        // SHA3_16B_cpu(output_digest, buf, DIGEST_SIZE, UUID_SIZE, num_uuid_read);
        // SHA3_16B_validation_v1(output_digest, buf, DIGEST_SIZE, UUID_SIZE, num_uuid_read);
        
        if(COMPRESS_HASHES) writeHashes_compact(output_fp, output_digest, DIGEST_SIZE, num_uuid_read, eof_flag);
        else writeHashes(output_fp, output_digest, DIGEST_SIZE, num_uuid_read, eof_flag);
        
        if(eof_flag) break;
    }

    free(output_digest);
    free(buf);
    free(uuid_raw_vals);
    // free(validation_digest);
    
    fclose(input_fp);
    fclose(output_fp);

    std::cout << "Number of UUIDs to read: "<< num_uuids_to_read
            << "\nTotal bytes read: " << total_bytes_read <<std::endl;

    return 0;
}


