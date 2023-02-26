// Copyright (C) Fisnik. All rights reserved.
#include <iostream>
#include <fstream>
#include <streambuf>
#include <exception>
#include <cassert>
#include <vector>
#include "filesystem"

#include "crypto++/sha.h"
#include "crypto++/aes.h"
#include "crypto++/osrng.h"
#include "crypto++/ccm.h"
#include "crypto++/modes.h"
#include "crypto++/hex.h"
#include "crypto++/files.h"
#include "crypto++/pwdbased.h"

namespace fs = std::filesystem;
using namespace CryptoPP;

constexpr auto ITERATIONS = 0x3E8;

// Encryption and Decryption of content previously encrypted with AES256 CBC mode. 
// Random Initialized Vector and random secret key are stored on a separate file.

void print_help(){}
void read_file(std::ifstream& in, std::vector<char>& buffer){}
void encrypt(std::vector<char>& data, std::ostream& out_key, std::ostream& out_data){}
std::string decrypt(SecByteBlock key, SecByteBlock iv, std::ifstream& encrypted_file){}
int main(int argc, const char* argv[]){ return 0; }