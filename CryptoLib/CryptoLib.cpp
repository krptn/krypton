#include "CryptoLib.h"
#include <pybind11/pybind11.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h> 

using namespace std;
namespace py = pybind11;

OSSL_PROVIDER *fips;
OSSL_PROVIDER *base;

bool fipsInit()
{
	fips = OSSL_PROVIDER_load(NULL, "fips");
	if (fips == NULL) {
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to load fips provider.");
		return false; 
	}
	EVP_set_default_properties(NULL, "fips=yes");

	base = OSSL_PROVIDER_load(NULL, "base");
    if (base == NULL) {
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to load fips provider.");
		return false; 
    }
	return true;
}

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

char* base64(char* data, int length) {
	int pl;
	if (length%3 == 0) {
		pl = length*4;
	} else {
		pl = 4*((length+(3-(length%3)))/3);
	}
	char* output = new char[pl+1];
	const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), (const unsigned char*)data, length);
	output[pl] = '\0';
	return output;
}

unsigned char *decode64(char* input, int length) {
	const auto pl = (length/4)*3;
	unsigned char* output = new unsigned char[pl+1];
	const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);
	output[pl] = '\0';
	return output;
}

py::bytes py_decode64(const char* input, int length) {
	const auto pl = (length/4)*3;
	unsigned char* output = new unsigned char[pl+1];
	const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);
	output[pl] = '\0';
	py::bytes result = py::bytes((const char*)output, pl).attr("rstrip")(py::bytes("\x00", 1));
	return result;
}

void handleErrors() {
	throw invalid_argument("Unable to perform cryptographic operation");
}

int __cdecl AddToStrBuilder(char* buffer, char* content, int len, int Optionalstrlen = 0) {
	int lena;
	if (Optionalstrlen == 0) {
		lena = strlen(content);
	}
	else {
		lena = Optionalstrlen;
	}
	memcpy_s(buffer + len, lena, content, lena);
	return 0;
}

PYBIND11_MODULE(__CryptoLib, m) {
	m.doc() = "Cryptographical component of PySec. Only for use inside the PySec module.";
	m.def("AESDecrypt", &AESDecrypt, "A function which decrypts the data. Args: text, key.", py::arg("ctext"), py::arg("key"));
	m.def("AESEncrypt", &AESEncrypt, "A function which encrypts the data. Args: text, key.", py::arg("text"), py::arg("key"));
	m.def("sha512", &pySHA512, "Hashes text with sha512", py::arg("text"));
	m.def("compHash", &compHash, "Compares hashes", py::arg("a"), py::arg("a"), py::arg("len")); 
	m.def("PBKDF2", &pyPBKDF2, "Performs PBKDF2 on text and salt", py::arg("text"), py::arg("salt"), py::arg("iter"), py::arg("saltLen"));
	m.def("fipsInit", &fipsInit,"Initialises openssl FIPS module.");
	m.def("createECCKey", &createECCKey, "Create a new ECC private key");
	m.def("getECCSharedKey", &getSharedKey, "Uses ECDH to get a shared 256-bit key", py::arg("privKey"), py::arg("pubKey"), 
		py::arg("salt"), py::arg("iter"));
	m.def("base64encode", &base64, "Base 64 encode data with length.", py::arg("data"), py::arg("length"));
	m.def("base64decode", &py_decode64, "Base 64 decode data with length.", py::arg("data"), py::arg("length"));
}
