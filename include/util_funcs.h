#pragma once
#ifndef UTIL_FUNCS_H
#define UTIL_FUNCS_H

#include<iostream>
#include<sstream>
#include<iomanip>
#include<cstdint>
#include<cmath>

#define GREEN "\033[1;32m"
#define BLUE "\033[1;34m"
#define NORMAL "\033[0m"
#define RED "\033[1;31m"
#define CYAN "\033[1;36m"
#define MAGENTA "\033[1;35m"

#define ERROR(err_str) {std::cerr<<RED<< err_str <<NORMAL<<std::endl; exit(EXIT_FAILURE);}

#define HEX_FORMAT 'a'
#define HEX_SUB (HEX_FORMAT - 48)


// Check if a given file is encoded using UTF-16 standard or not
bool isUTF16(char *filename);

// A function that takes a pointer to an array of hexadecimal characters, and converts exactly 2-bytes into a single byte of hex value
uint8_t decode_hexbyte(uint8_t *hexbyte);

// A function to create a file pointer for the `fread()` function to work with - involves some error-checking mechanism
FILE *createFilePointer(char *filename);

// extract 16-byte UUID data from a given file
size_t getUUID_bytes(FILE *fp, uint8_t *uuid_bytes, uint8_t *uuid_vals, size_t uuid_size, size_t total_num_byes_to_read, size_t *total_bytes_read);

// Convert an array of bytes into a readable string of Hex values
std::string bytesToHexString(uint8_t *bytes, size_t hexstring_size);

// function to write the evaluated hashes into an output file
void writeHashes(FILE *fp, uint8_t *digest_arr, size_t digest_size, size_t num_digests, uint8_t eof_flag);

// function to write the evaluated hashes into an output file in raw byte-format (non-delimited)
void writeHashes_compact(FILE *fp, uint8_t *digest_arr, size_t digest_size, size_t num_digests, uint8_t eof_flag);

// A utility function to compare two files and check if there's any data mismatch between them
int compare_files(FILE *fp_v1, FILE *fp_v2);


#endif
