/*++
    sha384.cpp
    
    Author: Fisnik
    Copyright (C) Fisnik
    
    Abstract:
        Performs Hashing using Secure Hash Algorithm 2, utilizing the SHA-384 cryptographic hash function.
    
    This source code is licensed under the MIT license found in the
    LICENSE file in the root directory of this source tree. 
--*/
#include <iostream>
#include "crypto++/hex.h"
#include "crypto++/sha.h"

using namespace CryptoPP;

void print_help() {}
void generate_sha384_hash(const std::string& msg, SHA384& hash, std::string& out){}
void pretty_print(const std::string& msg, const std::string& hash, const std::string& second_hash, bool is_match){}

int main(int argc, const char* argv[]) { return 0; }