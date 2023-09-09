// Copyright (C) Fisnik. All rights reserved.
#pragma once
#include <fstream>
#include <streambuf>
#include <exception>
#include <stdexcept>
#include <vector>
#include <cassert>
#include <Windows.h>
#include <string>

#if ((defined(_MSVC_LANG) && _MSVC_LANG >= 201703L) || __cplusplus >= 201703L && defined(__has_include))
#include <filesystem>
namespace fs = std::filesystem;
#else
#include "../third-party/filesystem/include/ghc/filesystem.hpp"
namespace fs = ghc::filesystem;
#endif

#include "../third-party/cryptopp/rsa.h"
#include "../third-party/cryptopp/osrng.h"
#include "../third-party/cryptopp/base64.h"
#include "../third-party/cryptopp/files.h"
#include "../third-party/cryptopp/pem.h"
#include "../third-party/cryptopp/modes.h"
#include "../third-party/cryptopp/sha.h"
#include "../third-party/cryptopp/ccm.h"
#include "../third-party/cryptopp/aes.h"
#include "../third-party/cryptopp/pwdbased.h"
#include "../third-party/cryptopp/hex.h"
#include "../third-party/cryptopp/cryptlib.h"

#include "../third-party/fmt/include/fmt/core.h"
#include "../third-party/fmt/include/fmt/color.h"

using namespace CryptoPP;

// Constants
constexpr auto ITERATIONS = 0x3E8;
constexpr auto MORE_SECURE_BIT = 4069;
constexpr auto DEFAULT_BIT = 2048;
constexpr auto DEFAULT_SESSION_KEY_BLOCK_SIZE = 256;

template <typename T>
T LoadKey(std::string filename)
{
	T key;
	FileSource fs(filename.c_str(), true);
	PEM_Load(fs, key);
	return key;
}

template <typename T>
void SaveKey(std::string filename, T &key)
{
	FileSink file(filename.c_str(), true);
	PEM_Save(file, key);
}

template <typename T>
void read_file(std::ifstream &in, std::vector<T> &buffer)
{
	if (in.is_open())
	{
		in.seekg(0, std::ios_base::end);
		size_t length = static_cast<size_t>(in.tellg());
		in.seekg(0, std::ios_base::beg);

		buffer.reserve(length);
		std::copy(std::istreambuf_iterator<char>(in),
				  std::istreambuf_iterator<char>(),
				  std::back_inserter(buffer));
	}
}