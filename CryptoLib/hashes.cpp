#include "CryptoLib.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <pybind11/pybind11.h>

using namespace std;
namespace py = pybind11;

const auto PBKDF2_HASH_ALGO = EVP_sha512;

int compHash(const void* a, const void* b, const size_t size)
{
	const unsigned char* _a = (const unsigned char*)a;
	const unsigned char* _b = (const unsigned char*)b;
	unsigned char result = 0;
	size_t i;

	for (i = 0; i < size; i++) {
		result |= _a[i] ^ _b[i];
	}

	return result; /* returns 0 if equal, nonzero otherwise */
}

py::bytes pyPBKDF2(char* text, int len, char* salt, int iter, int saltLen, int keylen) {
	py::gil_scoped_release release;
	char* key = new char[keylen];
	int a;
	a = PKCS5_PBKDF2_HMAC(text, len, (const unsigned char*) salt, saltLen, iter, PBKDF2_HASH_ALGO(), keylen, (unsigned char*)key);
	OPENSSL_cleanse(text, len);
	if (a != 1) {
		throw std::invalid_argument("Unable to hash data.");
	}
	py::gil_scoped_acquire acquire;
	return py::bytes(key, keylen);
}

py::bytes pyHKDF(char* secret, int len, char* salt, int saltLen, int keylen) {
	EVP_KDF *kdf;
	EVP_KDF_CTX *kctx;
	unsigned char* out = new unsigned char[keylen];
	OSSL_PARAM params[5], *p = params;

	kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	kctx = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);

	*p++ = OSSL_PARAM_construct_utf8_string("digest", (void*)"SHA512", 6);
	*p++ = OSSL_PARAM_construct_octet_string("key", secret, len);
	*p++ = OSSL_PARAM_construct_octet_string("info", (void*)"HKDF in __Cryptolib", 19);
	*p++ = OSSL_PARAM_construct_octet_string("key", salt, saltLen);
	*p = OSSL_PARAM_construct_end();
	if (EVP_KDF_derive(kctx, out, keylen, params) <= 0) {
		handleErrors();
	}
	EVP_KDF_CTX_free(kctx);
	py::bytes result = py::bytes((char*)out, keylen);
	delete[] out;
	return result;
}