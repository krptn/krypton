#include "CryptoLib.h"

#include <pybind11/pybind11.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#ifdef WIN
#include <openssl/applink.c>
#endif

using namespace std;
namespace py = pybind11;

OSSL_PROVIDER *fips;
OSSL_PROVIDER *base;

bool init = false;

bool fipsInit(char* osslConfig, char* modulePath) {
	if (init) {
		return true;
	}
	if (!OSSL_PROVIDER_set_default_search_path(NULL, modulePath)) {
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to add fips module to search path.");
		return false;
	}
	if (!OSSL_LIB_CTX_load_config(NULL, osslConfig)) {
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to load openssl configuration.");
		return false;
	}
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
		throw std::runtime_error("Failed to load base provider.");
		return false;
    }
	init = true;
	return true;
}

char* pymbToBuffer(py::bytes a) {
	py::iterator it = a.begin();
	int b = a.attr("__len__")().cast<int>();
	char* buf = new char[b];
	int i = 0;
	while (it != py::iterator::sentinel()){
		buf[i] = (char)((*it).cast<int>());
		++i;
		++it;
	};
	return buf;
}

char* pyStrToBuffer(py::str a) {
	py::iterator it = a.begin();
	int b = a.attr("__len__")().cast<int>();
	char* buf = new char[b];
	int i = 0;
	while (it != py::iterator::sentinel()){
		buf[i] = (*it).cast<char>();
		++i;
		++it;
	};
	return buf;
}

void handleErrors() {
	ERR_print_errors_fp(stderr);
	throw invalid_argument("Unable to perform cryptographic operation");
}

PYBIND11_MODULE(__CryptoLib, m) {
	m.doc() = "Cryptographical component of Krptn. Only for use inside the Krptn module.";
	m.def("AESDecrypt", &AESDecrypt, "A function which decrypts the data. Args: text, key.", py::arg("ctext_b"), py::arg("key"));
	m.def("AESEncrypt", &AESEncrypt, "A function which encrypts the data. Args: text, key.", py::arg("text"), py::arg("key"), py::arg("msglen"));
	m.def("compHash", &compHash, "Compares hashes", py::arg("a"), py::arg("a"), py::arg("len"));
	m.def("PBKDF2", &pyPBKDF2, "Performs PBKDF2 on text and salt", py::arg("text"), py::arg("textLen"), py::arg("salt"), 
		py::arg("iter"), py::arg("saltLen"), py::arg("keylen"));
	m.def("HKDF", &pyHKDF, py::arg("secret"), py::arg("len"), py::arg("salt"), py::arg("saltLen"), py::arg("keyLen"));
	m.def("fipsInit", &fipsInit,"Initialises OpenSSL 3 FIPS module. Repeated calls do nothing.", py::arg("osslConfig"), py::arg("modulePath"));
	m.def("createECCKey", &createECCKey, "Create a new ECC private key");
	m.def("ECDH", &ECDH, "Uses ECDH to get a shared 256-bit key", py::arg("privKey"), py::arg("pubKey"),
		py::arg("salt"), py::arg("keylen"));
	m.def("base64encode", &encode64, "Base 64 encode data with length.", py::arg("data"), py::arg("length"));
	m.def("base64decode", &decode64, "Base 64 decode data with length.", py::arg("data"), py::arg("length"));
	m.def("totpVerify", &verifyTOTP, "Verify TOTP with params", py::arg("secret"), py::arg("code"));
	m.def("genOTP", &genOTP, "Create a random PIN/OTP");
	m.def("sleepOutOfGIL", &sleepOutOfGIL, "Sleep for specified seconds while releasing the GIL.", py::arg("seconds")=5);
}