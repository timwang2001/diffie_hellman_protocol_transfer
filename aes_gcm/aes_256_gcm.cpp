#include "./lib/aes_256_gcm.h"

string aes_256_gcm_encrypt(string plain_text,CryptoPP::SecBlock<unsigned char>key,CryptoPP::SecBlock<unsigned char>iv)
{
    std::string cipher; //加密密文
    std::cout << "plain text: " << plain_text << std::endl;
    GCM< AES >::Encryption enc;  //加密对象enc
    enc.SetKeyWithIV(key, key.size(), iv);  //设置key和iv

    StringSource(plain_text, true, 
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(cipher)
        ) // AuthenticatedEncryptionFilter
    ); // StringSource

    std::cout << "cipher text: " << cipher << std::endl;
    return cipher;
}

string aes_256_gcm_decrypt(string cipher_text,CryptoPP::SecBlock<unsigned char>key,CryptoPP::SecBlock<unsigned char>iv)
{
    std::string recovered;
    GCM< AES >::Decryption dec;  //解密对象dec
    dec.SetKeyWithIV(key, key.size(), iv);

    StringSource s(cipher_text, true, 
        new AuthenticatedDecryptionFilter(dec,
            new StringSink(recovered)
        ) // AuthenticatedDecryptionFilter
    ); // StringSource
    std::cout << "recovered text: " << recovered << std::endl;
    return recovered;
}


void test_aes_256_gcm_encrypt_decrypt(string plain)  //测试程序，用的是prng随机生成的key和iv
{
    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));

    //SecByteBlock key(AES::DEFAULT_KEYLENGTH); //DEFAULT_KEYLENGTH是16字节，128位的AES密钥
    SecByteBlock key(AES::MAX_KEYLENGTH); //MAX_KEYLENGTH是32字节，256位密钥
    SecByteBlock iv(AES::BLOCKSIZE);

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::string cipher, recovered;

    std::cout << "plain text: " << plain << std::endl;

    GCM< AES >::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    StringSource(plain, true, 
        new AuthenticatedEncryptionFilter(e,
            new StringSink(cipher)
        ) // AuthenticatedEncryptionFilter
    ); // StringSource

    std::cout << "cipher text: " << cipher << std::endl;

    GCM< AES >::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    StringSource s(cipher, true, 
        new AuthenticatedDecryptionFilter(d,
            new StringSink(recovered)
        ) // AuthenticatedDecryptionFilter
    ); // StringSource
    std::cout << "recovered text: " << recovered << std::endl;
}