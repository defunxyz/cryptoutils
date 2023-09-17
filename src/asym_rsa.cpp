// Copyright (C) Fisnik. All rights reserved.
// Encryption and Decryption using RSA Public or RSA Private Key.
#include <iostream>
#include "common.h"

void print_help()
{
    std::string msg = R"(
asym_rsa -- AES256 with CBC Mode Encryption / Decryption using RSA Public-Private Key
Usage:
    asym_rsa  [-e file] [-k keyfile]
    asym_rsa  [-d file] [-k keyfile]

Command line options:
    -h --help	     Display the help.
    -e --encrypt     Encrypts a file.
    -d --decrypt     Decrypts an encrypted file.
    -k --key         Original key file.
    )";
	std::cout << msg << "\n";
}

void encrypt(const std::vector<char>& data, const RSA::PublicKey& pubkey, std::ostream& out_data)
{
    ByteQueue queue;
	AutoSeededRandomPool rand_seeder;
	RSAES_OAEP_SHA_Encryptor encryptor(pubkey);

	SecByteBlock session_key(AES::BLOCKSIZE);
	SecByteBlock iv(AES::BLOCKSIZE);

	rand_seeder.GenerateBlock(session_key, session_key.size());
	rand_seeder.GenerateBlock(iv, iv.size());

	ArraySource as(session_key, session_key.size(), true, /* pump all data */
		new PK_EncryptorFilter(rand_seeder, encryptor,
			new Redirector(queue)));

	SecByteBlock encrypted_session_key(queue.MaxRetrievable());
	ArraySink array_sink(encrypted_session_key, encrypted_session_key.size());
	queue.TransferTo(array_sink);

	CBC_Mode<AES>::Encryption cbc_aes_encryption;
	cbc_aes_encryption.SetKeyWithIV(session_key, sizeof(session_key), iv);

	std::string m_data;
	std::transform(data.begin(), data.end(), std::back_inserter(m_data), [](char c) { return c; });

	std::string result;
	StreamTransformationFilter stf(cbc_aes_encryption,
		new StringSink(result), BlockPaddingSchemeDef::DEFAULT_PADDING);
	stf.Put((const unsigned char*)m_data.data(), m_data.size());
	stf.MessageEnd();

	out_data.write((const char*)encrypted_session_key.data(), encrypted_session_key.size());
	out_data.write((const char*)iv.data(), iv.size());
	out_data.write(result.data(), result.size());
}

void decrypt(std::string& encrypted_content, SecByteBlock& session_key_data, const RSA::PrivateKey& decrykey, SecByteBlock& iv)
{
    std::string recovered;
	AutoSeededRandomPool rand_seeder;
	RSAES_OAEP_SHA_Decryptor decryptor(decrykey);

	SecByteBlock session_key(session_key_data.size());
	DecodingResult result = decryptor.Decrypt(rand_seeder, session_key_data, session_key_data.size(), session_key);

	CBC_Mode<AES>::Decryption cbc_aes_decryption;
	cbc_aes_decryption.SetKeyWithIV(session_key, sizeof(session_key), iv);

	try {

		StringSource src(encrypted_content, true,
			new StreamTransformationFilter(cbc_aes_decryption,
				new StringSink(recovered), BlockPaddingSchemeDef::DEFAULT_PADDING));
	}
	catch(CryptoPP::InvalidCiphertext e){
		std::cerr << e.what() << "\n";
	}

	std::cout << recovered << "\n";
}

int main(int argc, const char* argv[])
{
    	if (argc < 2) {
		std::cerr << "No arguments passed in\n";
		print_help();
		return -1;
	}

	if (strcmp(argv[1], "-d") == 0) {

		if (strcmp(argv[3], "-k") == 0) {

			std::string encrypted_content;
			std::vector<unsigned char> buffer;

			std::ifstream ifs(argv[2], std::ios::in | std::ios::binary);
			RSA::PrivateKey prvkey = load_key<RSA::PrivateKey>(argv[3]);

			read_file<unsigned char>(ifs, buffer);

			int data_section_size = buffer.size() - 509;
			int iv_section_size = data_section_size - 16;

			std::vector<char> session_key_block = { buffer.begin(), buffer.end() - data_section_size };
			std::vector<char> iv_data = { buffer.begin() + 509, buffer.end() - iv_section_size };
			std::vector<char> encrypted = { buffer.begin() + (509 + 16), buffer.end() };

			std::transform(encrypted.begin(), encrypted.end(), std::back_inserter(encrypted_content),
				[](char c) {
					return c;
				});

			SecByteBlock iv((const unsigned char*)iv_data.data(), iv_data.size());
			SecByteBlock block((const unsigned char*)session_key_block.data(), session_key_block.size());

			ifs.clear();
			ifs.close();

			decrypt(encrypted_content, block, prvkey, iv);
			return 0;
		}

		throw new std::runtime_error("No decryption key was found!");
		return -1;
	}
	else {

		if (strcmp(argv[3], "-k") == 0) {
			fs::path file(argv[2]);
			std::ifstream ifs(argv[2], std::ios::in | std::ios::binary);
			RSA::PublicKey pubkey = load_key<RSA::PublicKey>(argv[4]);

			std::vector<char> buffer;
			read_file<char>(ifs, buffer);
			std::string newfile = file.parent_path().string() + "\\" + file.stem().string() + "_encrypted" + file.extension().string();
			std::ofstream out(newfile, std::ios::binary | std::ios::out);
			
			encrypt(buffer, pubkey, out);

			ifs.close();
			out.close();
		}

		throw new std::runtime_error("No encryption key was found!");
		return -1;

	}

	return 0;
}