#include "CryptoLib.h"

#include <openssl/evp.h>
#include <pybind11/pybind11.h>

using namespace std;
namespace py = pybind11;

const int AES_KEY_LEN = 32;
int PBKDF2_STORAGE_ITERATIONS = 1000000;
int PBKDF2_KEY_ITERATIONS = 100000;
const int IV_SALT_LEN = 12;
const auto PBKDF2_HASH_ALGO = EVP_sha512;

char* __cdecl PBKDF2(char* text, char* salt) {
	char* key = new char[AES_KEY_LEN];
	int len = strlen(text);
	int a;
	a = PKCS5_PBKDF2_HMAC(text, len, (const unsigned char*) salt, IV_SALT_LEN, PBKDF2_KEY_ITERATIONS, PBKDF2_HASH_ALGO(), AES_KEY_LEN, (unsigned char*)key);
	OPENSSL_cleanse(text, len);
	if (a != 1) {
		throw std::invalid_argument("Unable to hash data.");
	}
	auto result = base64((const unsigned char*)key,AES_KEY_LEN);
	delete[] key;
	return result;
};

char* __cdecl hashForStorage(char* text) {
	char* key = new char[AES_KEY_LEN];
	char salt[IV_SALT_LEN];
	int len = strlen(text);
	RAND_bytes((unsigned char*)&salt, IV_SALT_LEN);
	int a;
	a = PKCS5_PBKDF2_HMAC(text, len, (unsigned char*)&salt, IV_SALT_LEN, PBKDF2_STORAGE_ITERATIONS,PBKDF2_HASH_ALGO(), AES_KEY_LEN, (unsigned char*)key);
	OPENSSL_cleanse(text, len);
	if (a != 1) {
		throw std::invalid_argument("Unable to hash data.");
	}
	auto new_b = base64((const unsigned char*)key,AES_KEY_LEN);
	return new_b;
}

py::bytes __cdecl getKeyFromPass(char* pwd) {
	char* key = new char[AES_KEY_LEN];
	char salt[IV_SALT_LEN];
	int len = strlen(pwd);
	RAND_bytes((unsigned char*)&salt, IV_SALT_LEN);
	int a;
	a = PKCS5_PBKDF2_HMAC(pwd, len, (unsigned char*)&salt, IV_SALT_LEN, PBKDF2_KEY_ITERATIONS, PBKDF2_HASH_ALGO(), AES_KEY_LEN, (unsigned char*)key);
	OPENSSL_cleanse(pwd, len);
	if (a != 1) {
		throw std::invalid_argument("Unable to hash data.");
	}
	return py::bytes(key,AES_KEY_LEN);
}