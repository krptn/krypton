#include "CryptoLib.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pybind11/pybind11.h>

using namespace std;
namespace py = pybind11;

const auto PBKDF2_HASH_ALGO = EVP_sha512;

py::bytes pyPBKDF2(char* text, int len, char* salt, int iter, int saltLen, int keylen) {
	//py::gil_scoped_release release;
	char* key = new char[keylen];
	int a;
	a = PKCS5_PBKDF2_HMAC(text, len, (const unsigned char*) salt, saltLen, iter, PBKDF2_HASH_ALGO(), keylen, (unsigned char*)key);
	OPENSSL_cleanse(text, len);
	if (a != 1) {
		throw std::invalid_argument("Unable to hash data.");
	}
	//py::gil_scoped_acquire acquire;
	return py::bytes(key, keylen);
}

