#include "CryptoLib.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <pybind11/pybind11.h>

using namespace std;
namespace py = pybind11;

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
	if (!PKCS5_PBKDF2_HMAC(text, len, (const unsigned char*) salt,
		saltLen, iter, PBKDF2_HASH, keylen, (unsigned char*)key)) {
			py::gil_scoped_acquire acquire;
			throw std::invalid_argument("Unable to hash data.");
		}
	OPENSSL_cleanse(text, len);
	py::gil_scoped_acquire acquire;
	py::bytes final = py::bytes(key, keylen);
	delete[] key;
	return final;
}

py::bytes pyHKDF(char* secret, int len, char* salt, int saltLen, int keylen) {
	EVP_KDF_CTX *kctx;
	unsigned char* out = new unsigned char[keylen];
	OSSL_PARAM params[4], *p = params;

	kctx = EVP_KDF_CTX_new(KDF);

	*p++ = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA512", 6);
	*p++ = OSSL_PARAM_construct_octet_string("key", secret, len);
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