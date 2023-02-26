// Copyright (C) Fisnik. All rights reserved.
#include <iostream>
#include "common.h"

// Encryption and Decryption of content previously encrypted with AES256 CBC mode. 
// Random Initialized Vector and random secret key are stored on a separate file.

void print_help(){}
void read_file(std::ifstream& in, std::vector<char>& buffer){}
void encrypt(std::vector<char>& data, std::ostream& out_key, std::ostream& out_data){}
std::string decrypt(SecByteBlock key, SecByteBlock iv, std::ifstream& encrypted_file){}
int main(int argc, const char* argv[]){ return 0; }