#include "CryptoLib.h"

#include <pybind11/pybind11.h>
#include <sodium.h>
#include <string>

using namespace std;
namespace py = pybind11;

int compHash(const void *a, const void *b, const size_t size)
{
	const volatile unsigned char *_a = (const unsigned char *)a;
	const volatile unsigned char *_b = (const unsigned char *)b;
	unsigned volatile char result = 0;
	volatile size_t i;

	for (i = 0; i < size; i++)
	{
		result |= _a[i] ^ _b[i];
	}

	return result; /* returns 0 if equal, nonzero otherwise */
}

py::bytes passwordHash(std::string text, std::string salt, int opsLimit, int memLimit, int keylen)
{
	if (salt.length() != crypto_pwhash_SALTBYTES) throw std::invalid_argument("Salt is of wrong length");
	py::gil_scoped_release release;
	auto key = unique_ptr<unsigned char[]>(new unsigned char[keylen]);
	const int hashStatus = crypto_pwhash(key.get(), keylen, text.c_str(), text.length(), (const unsigned char *)salt.c_str(),
					  opsLimit, memLimit,
					  crypto_pwhash_ALG_ARGON2ID13);
	py::gil_scoped_acquire acquire;
	py::bytes final = py::bytes((char *)key.get(), keylen);
	sodium_memzero((void*)key.get(), keylen);
	sodium_memzero((void*)text.c_str(), text.length());
	if (hashStatus != 0)
		throw std::runtime_error("Out of memory while hashing");
	return final;
}
