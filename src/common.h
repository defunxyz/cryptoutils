// Copyright (C) Fisnik. All rights reserved.
#pragma once
#include <fstream>
#include <streambuf>
#include <exception>
#include <stdexcept>
#include <vector>
#include <cassert>
#include <Windows.h>
#include <filesystem>

#include "crypto++/rsa.h"
#include "crypto++/osrng.h"
#include "crypto++/base64.h"
#include "crypto++/files.h"
#include "crypto++/pem.h"
#include "crypto++/modes.h"
#include "crypto++/sha.h"
#include "crypto++/ccm.h"
#include "crypto++/aes.h"
#include "crypto++/pwdbased.h"
#include "crypto++/hex.h"

namespace fs = std::filesystem;
using namespace CryptoPP;

// Constants
constexpr auto ITERATIONS = 0x3E8;
constexpr auto MORE_SECURE_BIT = 4069;
constexpr auto DEFAULT_BIT = 2048;
constexpr auto DEFAULT_SESSION_KEY_BLOCK_SIZE = 256;

template<typename T>
T LoadKey(std::string filename)
{
	T key;
	FileSource fs(filename.c_str(), true);
	PEM_Load(fs, key);
	return key;
}

template<typename T>
void SaveKey(std::string filename, T& key)
{
	FileSink file(filename.c_str(), true);
	PEM_Save(file, key);
}

template<typename T>
void read_file(std::ifstream& in, std::vector<T>& buffer)
{
	if (in.is_open()) {

		in.seekg(0, std::ios_base::end);
		size_t length = static_cast<size_t>(in.tellg());
		in.seekg(0, std::ios_base::beg);

		buffer.reserve(length);
		std::copy(std::istreambuf_iterator<char>(in),
			std::istreambuf_iterator<char>(),
			std::back_inserter(buffer));
	}
}