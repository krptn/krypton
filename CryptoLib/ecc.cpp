#include "CryptoLib.h"

#include <pybind11/pybind11.h>
#include <sodium.h>

#include <string>
#include <memory>
#include <stdexcept>
#include <cstddef>

using namespace std;
namespace py = pybind11;

py::tuple createECCKey()
{
	unsigned char publickey[crypto_box_PUBLICKEYBYTES];
	unsigned char secretkey[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(publickey, secretkey);
	py::tuple finalTuple = py::make_tuple(
		py::bytes((char *)&secretkey, crypto_box_SECRETKEYBYTES),
		py::bytes((char *)&publickey, crypto_box_PUBLICKEYBYTES));
	sodium_memzero(&secretkey, crypto_box_SECRETKEYBYTES);
	return finalTuple;
}

py::bytes encryptEcc(std::string privKey, std::string pubKey, std::string data)
{
	if (privKey.length() != crypto_box_SECRETKEYBYTES || pubKey.length() != crypto_box_PUBLICKEYBYTES)
		throw std::invalid_argument("Key is of wrong length in ECC Encrypt");
	const int outputLen = crypto_box_NONCEBYTES + data.length() + crypto_box_MACBYTES;
	auto output = unique_ptr<unsigned char[]>(new unsigned char[outputLen]);
	unsigned char *nonce = output.get();
	unsigned char *ciphertext = output.get() + crypto_box_NONCEBYTES;
	randombytes_buf(nonce, crypto_box_NONCEBYTES);
	const int encryptStatus = crypto_box_easy(ciphertext, (const unsigned char *)data.c_str(), data.length(), nonce,
											  (const unsigned char *)pubKey.c_str(), (const unsigned char *)privKey.c_str());
	sodium_memzero((void *)privKey.c_str(), privKey.length());
	sodium_memzero((void *)data.c_str(), data.length());
	if (encryptStatus != 0)
		throw std::invalid_argument("Error while encrypting with ECC");
	return py::bytes((char *)output.get(), outputLen);
}

py::bytes decryptEcc(std::string privKey, std::string pubKey, std::string data)
{
	if (privKey.length() != crypto_box_SECRETKEYBYTES || pubKey.length() != crypto_box_PUBLICKEYBYTES)
		throw std::invalid_argument("Key is of wrong length in ECC Encrypt");
	if (data.length() <= crypto_box_NONCEBYTES + crypto_box_MACBYTES)
		throw std::invalid_argument("Wrong data length in decryptEcc");
	const int outputLen = data.length() - crypto_box_NONCEBYTES - crypto_box_MACBYTES;
	auto output = unique_ptr<unsigned char[]>(new unsigned char[outputLen]);
	unsigned char *nonce = (unsigned char *)data.c_str();
	unsigned char *ciphertext = (unsigned char *)data.c_str() + crypto_box_NONCEBYTES;
	const int decryptStatus = crypto_box_open_easy(output.get(), ciphertext, data.length() - crypto_box_NONCEBYTES, nonce,
							 (unsigned char *)pubKey.c_str(), (unsigned char *)privKey.c_str());
	py::bytes finalOuput = py::bytes((char *)output.get(), outputLen);
	sodium_memzero((void *)privKey.c_str(), privKey.length());
	sodium_memzero((void *)output.get(), outputLen);
	if (decryptStatus != 0)
		throw std::invalid_argument("Unable to decrypt data in ECC");
	return finalOuput;
}
