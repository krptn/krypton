#include "CryptoLib.h"

#include <pybind11/pybind11.h>
#include <sodium.h>

using namespace std;
namespace py = pybind11;

py::tuple createECCKey()
{
	unsigned char publickey[crypto_box_PUBLICKEYBYTES];
	unsigned char secretkey[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(publickey, secretkey);
	py::tuple finalTuple = py::make_tuple(
		py::bytes((char *)&publickey, crypto_box_PUBLICKEYBYTES),
		py::bytes((char *)&secretkey, crypto_box_SECRETKEYBYTES));
	return finalTuple;
}

py::bytes encryptEcc(std::string privKey, std::string pubKey, std::string data)
{
	const int outputLen = crypto_box_NONCEBYTES + data.length() + crypto_box_MACBYTES;
	auto output = unique_ptr<unsigned char[]>(new unsigned char[outputLen]);
	unsigned char *nonce = output.get();
	unsigned char *ciphertext = output.get() + crypto_box_NONCEBYTES;
	randombytes_buf(nonce, crypto_box_NONCEBYTES);
	if (crypto_box_easy(ciphertext, (const unsigned char *)data.c_str(), data.length(), nonce,
						(const unsigned char *)pubKey.c_str(), (const unsigned char *)privKey.c_str()) != 0)
	{
		sodium_memzero((void *)privKey.c_str(), privKey.length());
		sodium_memzero((void *)data.c_str(), data.length());
		throw std::invalid_argument("Error while encrypting with ECC");
	}
	return py::bytes((char*)output.get(), outputLen);
}

py::bytes decryptEcc(std::string privKey, std::string pubKey, std::string data)
{

}
