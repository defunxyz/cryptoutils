// Copyright (C) Fisnik. All rights reserved.
#include <iostream>
#include "common.h"

// Encryption and Decryption of content previously encrypted with AES256 CBC mode. 
// Random Initialized Vector and random secret key are stored on a separate file.

void print_help()
{
    std::string msg = R"(
aes256.exe -- Advanced Encryption Standard 256 with CBC Mode
Usage:
	aes256  [-e file]
	aes256  [-d file] [-k keyfile]

Command line options:
	-h --help	       Display the help.
	-e --encrypt       Encrypts a file.
	-d --decrypt       Decrypts an encrypted file.
	-k --key           Original key file.
    )";

    std::cout << msg << "\n";
}

void encrypt(std::vector<char>& data, std::ostream& out_key, std::ostream& out_data)
{
    AutoSeededRandomPool rand_seeder;
	
	SecByteBlock key(AES::MAX_KEYLENGTH);
	SecByteBlock iv(AES::BLOCKSIZE);
	SecByteBlock salt(4);

	PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
	CBC_Mode<AES>::Encryption cbc_aes_encryption;

	rand_seeder.GenerateBlock(key, key.size());
	rand_seeder.GenerateBlock(iv, iv.size());
	rand_seeder.GenerateBlock(salt, salt.size());

	byte derived_key[AES::MAX_KEYLENGTH];
	pbkdf2.DeriveKey(derived_key, sizeof(derived_key), 0, 
		(byte*)key.data(), key.size(), (byte*)iv.data(), iv.size(), ITERATIONS);
	cbc_aes_encryption.SetKeyWithIV(derived_key, sizeof(derived_key), iv);

	std::string m_data;
	std::transform(data.begin(), data.end(), std::back_inserter(m_data), [](char c) { return c; });

	std::string m_salt = std::string(reinterpret_cast<const char*>(salt.data()), salt.size());
	m_data = m_salt + m_data;

	std::string result;
	StreamTransformationFilter stf(cbc_aes_encryption, 
		new StringSink(result), BlockPaddingSchemeDef::DEFAULT_PADDING);
	stf.Put((const unsigned char*)m_data.data(), m_data.size());
	stf.MessageEnd();

	out_key.write((const char*)iv.data(), iv.size());
	out_key.write((const char*)derived_key, sizeof(derived_key));
	out_data.write(result.data(), result.size());
}

std::string decrypt(SecByteBlock key, SecByteBlock iv, std::ifstream& encrypted_file)
{
    assert(encrypted_file.is_open());
	std::string recovered;
	std::string data((std::istreambuf_iterator<char>(encrypted_file)),
		(std::istreambuf_iterator<char>()));
	
	CBC_Mode<AES>::Decryption cbc_aes_decryption;
	cbc_aes_decryption.SetKeyWithIV(key, 32, iv);

	StringSource src(data, true, 
		new StreamTransformationFilter(cbc_aes_decryption, 
			new StringSink(recovered), BlockPaddingSchemeDef::DEFAULT_PADDING));

	recovered.erase(0, 4); // Erasing first 4 bytes of the salt.
	return recovered;
}

int main(int argc, const char* argv[])
{
    if (argc < 2) {
		std::cerr << "No arguments passed in\n";
		print_help();
		return -1;
	}
	
	if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		print_help();
		return -1;
	}
	else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--decrypt") == 0) {

		if (strcmp(argv[3], "-k") == 1) {
			std::cerr << "No key file was supplied, terminating.";
				return -1;
		}

		if(strcmp(argv[3], "-k") == 0 || strcmp(argv[1], "--key") == 0) {
			if (strcmp(argv[4], "") == 0) {
				std::cerr << "No key file was supplied, terminating.";
				return -1;
			}

			std::ifstream ifs(argv[4], std::ifstream::binary);
			std::ifstream enc(argv[2], std::ifstream::binary);

			std::vector<char> buffer;
			read_file(ifs, buffer);

			std::vector<char> iv_data = { buffer.begin(), buffer.end() - 32 };
			std::vector<char> secret_key_data = { buffer.begin() + 16, buffer.end() };

			ifs.clear();
			ifs.close();

			try {
				std::cout << decrypt(SecByteBlock((const unsigned char*)secret_key_data.data(), secret_key_data.size()),
					SecByteBlock((const unsigned char*)iv_data.data(), iv_data.size()), enc) << std::endl;
			}
			catch (const CryptoPP::Exception& e) {
				std::cerr << e.what() << std::endl;
			}
		}
	}
	else {
		
		fs::path file(argv[2]);
		std::ifstream ifs(argv[2], std::ifstream::binary);

		std::vector<char> buffer;
		read_file(ifs, buffer);

		std::string key_file = file.parent_path().string() + "\\" + file.stem().string() + ".key";
		std::string enc_filename = file.parent_path().string() + "\\" + file.stem().string() + "_encrypted" + file.extension().string();

		std::ofstream keyout(key_file, std::ios::binary);
		std::ofstream out(enc_filename, std::ios::binary | std::ios::out);

		encrypt(buffer, keyout, out);

		keyout.close();
		out.close();
	}

    std::cin.get();
    return 0; 
}