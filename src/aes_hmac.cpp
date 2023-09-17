// Copyright (C) Fisnik. All rights reserved.
#include <iostream>
#include "common.h"

std::string encrypt(std::string data, SecByteBlock &secret_key)
{

	AutoSeededRandomPool rand_seeder;
	SecByteBlock iv(AES::BLOCKSIZE);
	rand_seeder.GenerateBlock(iv, sizeof(iv));

	std::string hmac_sigature;
	HMAC<SHA256> hmac(secret_key, secret_key.size());
	StringSource ss(data, true,
					new HashFilter(hmac,
								   new StringSink(hmac_sigature)));

	CBC_Mode<AES>::Encryption aes;
	aes.SetKeyWithIV(secret_key, sizeof(secret_key), iv);

	std::string encrypted_data;
	StreamTransformationFilter stf(aes, new StringSink(encrypted_data), BlockPaddingSchemeDef::DEFAULT_PADDING);
	stf.Put(reinterpret_cast<const unsigned char *>(data.data()), data.size());
	stf.MessageEnd();

	std::string final_block;
	std::string iv_str = std::string(reinterpret_cast<const char *>(iv.data()), iv.size());

	encrypted_data = iv_str + encrypted_data;
	final_block = hmac_sigature + encrypted_data;

	return final_block;
}

std::string decrypt(std::string &data, SecByteBlock &secret_key)
{

	AutoSeededRandomPool rand_seeder;
	int digest_size = {SHA256::DIGESTSIZE}, iv_length = {16}, data_size = {0}, start = {0};

	data_size = data.length() - (digest_size + iv_length);
	start = digest_size + iv_length;

	std::string hmac_signature = data.substr(0, data_size + 1);
	std::string iv_str = data.substr(digest_size, iv_length + 1);
	std::string body = data.substr(start, data_size + 1);

	std::string tmp_signature;
	SecByteBlock iv(reinterpret_cast<byte const *>(iv_str.data()), AES::BLOCKSIZE);

	CBC_Mode<AES>::Decryption cbc_aes_decryption;
	cbc_aes_decryption.SetKeyWithIV(secret_key, secret_key.size(), iv, iv.size());

	std::string recovered;
	StringSource src(body, true,
					 new StreamTransformationFilter(cbc_aes_decryption,
													new StringSink(recovered), BlockPaddingSchemeDef::DEFAULT_PADDING));

	try
	{
		HMAC<SHA256> hmac(secret_key, secret_key.size());
		StringSource ss(body, true,
						new HashFilter(hmac,
									   new StringSink(tmp_signature)));

		StringSource s(tmp_signature, true,
					   new HashVerificationFilter(hmac, NULL, HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END));

		return recovered;
	}
	catch (const HashVerificationFilter::HashVerificationFailed &e)
	{
		// HashVerificationFilter::HashVerificationFailed Class Reference
		// https://www.cryptopp.com/docs/ref/class_hash_verification_filter_1_1_hash_verification_failed.html#details
		return "HMAC's mismatch: the secret key has been tampered with.";
	}
}

int main(int argc, char *argv[])
{
	std::string message = "Hello world, this is secret message!";
	std::string encrypted_data;
	std::string decrypted_data;

	AutoSeededRandomPool rand_seeder;
	SecByteBlock secret_key(AES::BLOCKSIZE);
	rand_seeder.GenerateBlock(secret_key, secret_key.size());

	try
	{
		encrypted_data = encrypt(message, secret_key);
	}
	catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
	}

	try
	{
		decrypted_data = decrypt(encrypted_data, secret_key);
	}
	catch (const CryptoPP::Exception &e)
	{
		std::cerr << e.what() << std::endl;
	}

	std::cout << decrypted_data << std::endl;
	std::cin.get();

	return 0;
}