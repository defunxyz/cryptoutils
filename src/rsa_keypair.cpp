// Copyright (C) Fisnik. All rights reserved.
// Generates RSA Public Private KeyPair based on PEM X.509
#include <iostream>
#include "common.h"

void print_help()
{
    std::string msg = R"(
rsa_keypair -- RSA Encrypting Decrypting Key Generator
Usage:
    rsa_keypair  [-f name] [-b number]
    rsa_keypair  [-f name] [-o destination] [-b number]

Command line options:
    -f, --filename     A name for the key.
    -o, --out          Output destination.
    -b, --bit          Bit long modulus. [default: 4069]
    -h --help	       Display the help.
    )";
	std::cout << msg << "\n";
}

void generare_key_pair(std::string name, std::filesystem::path path, const char* ext = "pem", int bit = 4069)
{
    bit = (bit < 0 || bit == 0) ? 4069 : bit;

	AutoSeededRandomPool random_pool;

	RSA::PrivateKey rsa_private_key;
	rsa_private_key.GenerateRandomWithKeySize(random_pool, bit);

	RSA::PublicKey rsa_public_key(rsa_private_key);

	fs::path copy(path); // Make a copy for second concatenation due to continuation which causes duplication path + new filename resulting in errror
	fs::path prvfile  = path /= name + "_decrypt." + ext;
	fs::path pubfile = copy /= name + "_encrypt." + ext;

	save_key<RSA::PrivateKey>(prvfile.string(), rsa_private_key);
	save_key<RSA::PublicKey>(pubfile.string(), rsa_public_key);
}

int main(int argc, const char* argv[]) 
{
    if (argc < 2) {
		std::cerr << "No arguments passed in";
		print_help();
		return -1;
	}

	if(strcmp(argv[1], "-h") == 0) {
		print_help();
		return -1;
	}
	else if (strcmp(argv[1], "-f") == 0 && strcmp(argv[3], "-o") == 0 && strcmp(argv[5], "-b") == 0) {
		std::string filename = argv[2];
		fs::path destination(argv[4]);
		int bit = std::stoi(argv[6]);
		generare_key_pair(filename, destination, "pem", bit);
	}
	else if (strcmp(argv[1], "-f") == 0 && strcmp(argv[3], "-o") == 0)
	{
		std::string filename = argv[2];
		fs::path destination(argv[4]);
		generare_key_pair(filename, destination);
	}
	else {
		std::string filename = argv[2];
		fs::path filepah(filename.c_str());

		if (filepah.is_absolute()) {
			generare_key_pair(filepah.stem().string(), filepah.parent_path());

		}
		else {
			generare_key_pair(filepah.stem().string(), filepah.parent_path());
		}
	}
	
	return 0;
}