#include "CryptoLib.h"

#include <pybind11/pybind11.h>
#include <string>
#include <sodium.h>
#include <stdint.h>

using namespace std;
namespace py = pybind11;

py::bytes encrypt(std::string text, std::string key)
{
	if (key.length() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
		throw std::invalid_argument("Key is of wrong size");
	auto output = unique_ptr<unsigned char[]>(new unsigned char[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + text.length() + crypto_aead_xchacha20poly1305_ietf_ABYTES]);
	unsigned char *nonce = output.get();
	unsigned char *ciphertext = output.get() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
	long long unsigned int ciphertext_len;
	randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
	crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
											   (const unsigned char *)text.c_str(), text.length(),
											   (unsigned char *)NULL, (size_t)NULL,
											   (unsigned char *)NULL, nonce, (const unsigned char *)key.c_str());
	sodium_memzero((void *)key.c_str(), key.length());
	sodium_memzero((void *)text.c_str(), text.length());
	return py::bytes((char *)output.get(), ciphertext_len + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
}

py::bytes decrypt(std::string ctext, std::string key)
{
	if (key.length() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
		throw std::invalid_argument("Key is of wrong size");
	if (ctext.length() <= crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)
		throw std::invalid_argument("Ciphertext is of wrong size in decrypt.");
	auto output = unique_ptr<unsigned char[]>(new unsigned char[ctext.length() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES - crypto_aead_xchacha20poly1305_ietf_ABYTES]);
	long long unsigned int decryptedLen;
	unsigned char *cTextTrimmed = (unsigned char *)ctext.c_str() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
	size_t ctextLen = ctext.length() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
	const int decryptStatus = crypto_aead_xchacha20poly1305_ietf_decrypt(output.get(), &decryptedLen,
																		 (unsigned char *)NULL,
																		 cTextTrimmed, ctextLen,
																		 (unsigned char *)NULL,
																		 (size_t)NULL,
																		 (unsigned char *)ctext.c_str(), (unsigned char *)key.c_str());
	sodium_memzero((void *)key.c_str(), key.length());
	py::bytes data = py::bytes((char *)output.get(), decryptedLen);
	sodium_memzero((void *)output.get(), decryptedLen);
	if (decryptStatus != 0)
		throw std::invalid_argument("Unable to decrypt.");
	return data;
}
