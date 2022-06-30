#include "../lib/aes_256_gcm.h"

string aes_256_gcm_encrypt(string plain_text, CryptoPP::SecBlock<unsigned char> key, CryptoPP::SecBlock<unsigned char> iv)
{
	std::string cipher; //加密密文
	std::cout << "plain text: " << plain_text << std::endl;
	GCM<AES>::Encryption enc;						  //加密对象enc
	enc.SetKeyWithIV(key, key.size(), iv, iv.size()); //设置key和iv
													  // std::cout << "start encrypting"<< std::endl;
	StringSource(plain_text, true,
				 new AuthenticatedEncryptionFilter(enc,
												   new StringSink(cipher)) // AuthenticatedEncryptionFilter
	);																	   // StringSource

	std::cout << "cipher text: " << cipher << " len=" << cipher.length() << std::endl;
	return cipher;
}

string aes_256_gcm_decrypt(string cipher_text, CryptoPP::SecBlock<unsigned char> key, CryptoPP::SecBlock<unsigned char> iv)
{
	std::string recovered;
	GCM<AES>::Decryption dec; //解密对象dec
	dec.SetKeyWithIV(key, key.size(), iv, iv.size());

	StringSource s(cipher_text, true,
				   new AuthenticatedDecryptionFilter(dec,
													 new StringSink(recovered)) // AuthenticatedDecryptionFilter
	);																			// StringSource
	std::cout << "recovered text: " << recovered << std::endl;
	return recovered;
}

SecByteBlock generateiv()
{
	AutoSeededRandomPool prng;
	SecByteBlock iv(AES::BLOCKSIZE);
	prng.GenerateBlock(iv, iv.size());
	return iv;
}

string test_aes_256_gcm_encrypt_decrypt(string plain, SecByteBlock key, SecByteBlock iv, int flag) //测试程序，用的是prng随机生成的key和iv
{
	HexEncoder encoder(new FileSink(std::cout));

	std::string cipher, recovered;
	if (flag == 1)
	{
		std::cout << "plain text: " << plain << std::endl;

		GCM<AES>::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		StringSource(plain, true,
					 new AuthenticatedEncryptionFilter(e,
													   new StringSink(cipher)) // AuthenticatedEncryptionFilter
		);																	   // StringSource
		return cipher;
	}
	else
	{
		GCM<AES>::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		StringSource s(plain, true,
					   new AuthenticatedDecryptionFilter(d,
														 new StringSink(recovered)) // AuthenticatedDecryptionFilter
		);																			// StringSource
		std::cout << "recovered text: " << recovered << std::endl;
		return recovered;
	}
}