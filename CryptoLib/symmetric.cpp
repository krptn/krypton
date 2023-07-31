#include "CryptoLib.h"

#include <pybind11/pybind11.h>
#include <string>
#include <sodium.h>

using namespace std;
namespace py = pybind11;

extern EVP_CIPHER *AES_ALGO;

py::bytes encrypt(std::string text, std::string key)
{
	if (key.length() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
		throw std::invalid_argument("Key is of wrong size");
	auto output = unique_ptr<unsigned char[]>(new unsigned char[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + text.length() + crypto_aead_xchacha20poly1305_ietf_ABYTES]);
	unsigned char *nonce = output.get();
	unsigned char *ciphertext = output.get() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
	uint64_t ciphertext_len;
	randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
	crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
											   (const unsigned char *)text.c_str(), text.length(),
											   NULL, NULL,
											   NULL, nonce, (const unsigned char *)key.c_str());
	sodium_memzero((void *)key.c_str(), key.length());
	sodium_memzero((void *)text.c_str(), text.length());
	return py::bytes((char *)output.get(), ciphertext_len+crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
}

py::bytes decrypt(std::string ctext, std::string key)
{
	if (key.length() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
		throw std::invalid_argument("Key is of wrong size");
	auto output = unique_ptr<unsigned char[]>(new unsigned char[ctext.length() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES - crypto_aead_xchacha20poly1305_ietf_ABYTES]);
	uint64_t decryptedLen;
	unsigned char *cTextTrimmed = (unsigned char *)ctext.c_str() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
	uint64_t ctextLen = ctext.length() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
	if (crypto_aead_xchacha20poly1305_ietf_decrypt(output.get(), &decryptedLen,
												   NULL,
												   cTextTrimmed, ctextLen,
												   NULL,
												   NULL,
												   (unsigned char *)ctext.c_str(), (unsigned char *)key.c_str()) != 0)
	{
		sodium_memzero((void *)key.c_str(), key.length());
		sodium_memzero((void *)output.get(), decryptedLen);
		throw std::invalid_argument("Unable to decrypt.");
	}
	sodium_memzero((void *)key.c_str(), key.length());
	py::bytes data = py::bytes((char *)output.get(), decryptedLen);
	sodium_memzero((void *)output.get(), decryptedLen);
	return data;
}
