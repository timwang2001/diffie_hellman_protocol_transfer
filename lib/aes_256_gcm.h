//需要提前下载安装cryptopp库，并作为头文件包含
#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/gcm.h"
#include "cryptopp/filters.h"
#include "cryptopp/cryptlib.h"
#include <iostream>
#include <string>

using namespace CryptoPP;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AES;
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;
using std::string;
using std::cout;
using std::endl;

string aes_256_gcm_encrypt(string plain_text,CryptoPP::SecBlock<unsigned char>key,CryptoPP::SecBlock<unsigned char>iv);
string aes_256_gcm_decrypt(string cipher_text,CryptoPP::SecBlock<unsigned char>key,CryptoPP::SecBlock<unsigned char>iv);
void test_aes_256_gcm_encrypt_decrypt(string plain);