// Copyright (C) Fisnik. All rights reserved.
// Generates RSA Public Private KeyPair based on PEM X.509
#include <iostream>
#include <string>
#include <filesystem>
#include <Windows.h>

#include "crypto++/rsa.h"
#include "crypto++/osrng.h"
#include "crypto++/files.h"
#include "crypto++/base64.h"
#include "crypto++/pem.h"

namespace fs = std::filesystem;
using namespace CryptoPP;

template<typename T>
T load_key(const std::string& filename){}

template<typename T>
void save_key(const std::string filename, T& key){}

void generare_key_pair(const std::string name, const fs::path path, const char* ext = "pem", int bit = 4069) {}

void print_help(){}

int main(int argc, const char* argv[]) { return 0; }