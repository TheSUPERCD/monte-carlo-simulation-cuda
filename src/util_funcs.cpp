#include <util_funcs.h>

// Check if a given file is encoded using UTF-16 standard or not
bool isUTF16(char *filename){
    bool ret = false;
    FILE* fp = std::fopen(filename, "rb");
    if(fp == nullptr) ERROR("\nERROR: Invalid filename!")
    else{
        uint16_t flag[1];
        int _uv = fread(flag, sizeof(uint16_t), 1, fp);
        if(_uv == 0) ERROR("\nERROR: Input file is empty!")
        if(flag[0] == 65279) ret = true;
        fclose(fp);
    }
    return ret;
}

// A function that takes a pointer to an array of hexadecimal characters, and converts exactly 2-bytes into a single byte of hex value
uint8_t decode_hexbyte(uint8_t *hexbyte){
    uint8_t retval;
    u_int8_t tmp = hexbyte[0] - '0';
    if(tmp < HEX_SUB) retval = tmp << 4;
    else retval = (10 + (tmp % (HEX_SUB))) << 4;

    tmp = hexbyte[1] - '0';
    if(tmp < HEX_SUB) retval += tmp;
    else retval += (10 + (tmp % (HEX_SUB)));

    return retval;
}

// A function to create a file pointer for the `fread()` function to work with - involves some error-checking mechanism
FILE *createFilePointer(char *filename){
    bool encoding_flag = isUTF16(filename);
    FILE* fp = std::fopen(filename, "rb");
    if(encoding_flag){
        uint16_t flag_data[1];
        int _uv = fread(flag_data, sizeof(uint16_t), 1, fp);
        if(_uv == 0) ERROR("\nERROR: Input file is empty!")
        std::cerr<<CYAN<< "\n[*] Detected UTF-16 encoding. Discarding initial bytes...\n" <<NORMAL<<std::endl;
    }
    return fp;
}

// extract 16-byte UUID data from a given file
size_t getUUID_bytes(FILE *fp, uint8_t *uuid_bytes, uint8_t *uuid_vals, size_t uuid_size, size_t total_num_byes_to_read, size_t *total_bytes_read){
    // The total number of characters an UUID can have is twice the UUID's size in bytes + a single byte for the newline('\n') character
    int uuid_char_length = (uuid_size*2 + 1);
    
    size_t bytes_read = fread(uuid_vals, sizeof(uint8_t), total_num_byes_to_read, fp);
    if(bytes_read == 0){
        if(feof(fp)) return bytes_read;
        else if(ferror(fp)) ERROR("\nERROR: Unexpected error occurred while reading file!")
    }
    else{
        *total_bytes_read += bytes_read;
        bytes_read = ceil((double)bytes_read/(uuid_size*2 + 1)); //  turned into num_uuids_read
    }

    for(size_t i=0;i<bytes_read;i++){
        size_t uuid_idx = i*uuid_size;
        uint8_t *uuid_vals_pointer = uuid_vals + i*(uuid_char_length);
        uuid_bytes[uuid_idx +  0] = decode_hexbyte(uuid_vals_pointer +  0);
        uuid_bytes[uuid_idx +  1] = decode_hexbyte(uuid_vals_pointer +  2);
        uuid_bytes[uuid_idx +  2] = decode_hexbyte(uuid_vals_pointer +  4);
        uuid_bytes[uuid_idx +  3] = decode_hexbyte(uuid_vals_pointer +  6);
        uuid_bytes[uuid_idx +  4] = decode_hexbyte(uuid_vals_pointer +  8);
        uuid_bytes[uuid_idx +  5] = decode_hexbyte(uuid_vals_pointer + 10);
        uuid_bytes[uuid_idx +  6] = decode_hexbyte(uuid_vals_pointer + 12);
        uuid_bytes[uuid_idx +  7] = decode_hexbyte(uuid_vals_pointer + 14);
        uuid_bytes[uuid_idx +  8] = decode_hexbyte(uuid_vals_pointer + 16);
        uuid_bytes[uuid_idx +  9] = decode_hexbyte(uuid_vals_pointer + 18);
        uuid_bytes[uuid_idx + 10] = decode_hexbyte(uuid_vals_pointer + 20);
        uuid_bytes[uuid_idx + 11] = decode_hexbyte(uuid_vals_pointer + 22);
        uuid_bytes[uuid_idx + 12] = decode_hexbyte(uuid_vals_pointer + 24);
        uuid_bytes[uuid_idx + 13] = decode_hexbyte(uuid_vals_pointer + 26);
        uuid_bytes[uuid_idx + 14] = decode_hexbyte(uuid_vals_pointer + 28);
        uuid_bytes[uuid_idx + 15] = decode_hexbyte(uuid_vals_pointer + 30);
    }
    return bytes_read;
}

// Convert an array of bytes into a readable string of Hex values
std::string bytesToHexString(uint8_t *bytes, size_t hexstring_size){
    std::stringstream ss;
    ss<<std::hex<<std::setfill('0');
    for(int i=0;i<(int)hexstring_size;i++){
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    std::string retval = ss.str();
    return retval;
}

// function to write the evaluated hashes into an output file in newline('\n') delimited Hex-String format
void writeHashes(FILE *fp, uint8_t *digest_arr, size_t digest_size, size_t num_digests, uint8_t eof_flag){
    for(size_t i=0;i<num_digests-eof_flag;i++){
        std::string d1 = bytesToHexString(digest_arr + i*digest_size, digest_size) + "\n";
        fwrite(d1.c_str(), sizeof(char), d1.size(), fp);
    }
    if(eof_flag){
        std::string d2 = bytesToHexString(digest_arr + (num_digests-1)*digest_size, digest_size);
        fwrite(d2.c_str(), sizeof(char), d2.size(), fp);
    }
}

// function to write the evaluated hashes into an output file in raw byte-format (non-delimited)
void writeHashes_compact(FILE *fp, uint8_t *digest_arr, size_t digest_size, size_t num_digests, uint8_t eof_flag){
    fwrite(digest_arr, sizeof(uint8_t), digest_size*num_digests, fp);
}

// A utility function to compare two files and check if there's any data mismatch between them
int compare_files(FILE *fp_v1, FILE *fp_v2){
    size_t bytes_read_v1;
    size_t bytes_read_v2;
    uint8_t buf_v1[BUFSIZ];
    uint8_t buf_v2[BUFSIZ];
    while (true){
        bytes_read_v1 = fread(buf_v1, sizeof(uint8_t), BUFSIZ, fp_v1);
        bytes_read_v2 = fread(buf_v2, sizeof(uint8_t), BUFSIZ, fp_v2);
        
        if(bytes_read_v1 == bytes_read_v2){
            if(bytes_read_v1){
                for(int i=0;i<(int)bytes_read_v1;i++){
                    if(buf_v1[i] != buf_v2[i]) return EXIT_FAILURE;
                }
            }
            else break;
        }
        else return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}



// int main(int argc, char **argv){
//     char *filename_v1 = argv[1];
//     char *filename_v2 = argv[2];
    
//     FILE *fp_v1 = fopen(filename_v1, "rb");
//     FILE *fp_v2 = fopen(filename_v2, "rb");

//     if(compare_files(fp_v1, fp_v2)){
//         std::cout<<"\nFILES DID NOT MATCH!!\n";
//     }
//     else{
//         std::cout<<"\nFILES PERFECTLY MATCHED!!\n";
//     }

//     fclose(fp_v1);
//     fclose(fp_v2);

//     return 0;
// }
