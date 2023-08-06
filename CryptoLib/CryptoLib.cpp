#include "CryptoLib.h"

#include <pybind11/pybind11.h>
#include <sodium.h>

#include <stdexcept>

using namespace std;
namespace py = pybind11;

bool initHappened = false;

bool init()
{
	if (initHappened)
		return true;
	if (sodium_init() < 0)
        throw std::runtime_error("Failed to init LibSodium");
	initHappened = true;
	return true;
}

PYBIND11_MODULE(__CryptoLib, m)
{
	m.doc() = "Cryptographical component of Krptn. Only for use inside the Krptn module.";
	m.def("decrypt", &decryptWithSecret, "A function which decrypts the data. Args: ctext, key.", py::arg("ctext"), py::arg("key"));
	m.def("encrypt", &encryptWithSecret, "A function which encrypts the data. Args: text, key.", py::arg("text"), py::arg("key"));
	m.def("compHash", &compHash, "Compares hashes", py::arg("a"), py::arg("a"), py::arg("len"));
	m.def("passwordHash", &passwordHash, "Performs password hashing on text and salt", py::arg("text"), py::arg("salt"), py::arg("opsLimit"), py::arg("memLimit"), py::arg("keyLen"));
	m.def("encryptEcc", &encryptEcc, "Encrypts data using public/private keys", py::arg("privKey"), py::arg("pubKey"), py::arg("data"));
	m.def("decryptEcc", &decryptEcc, "Decrypts data using public/private keys", py::arg("privKey"), py::arg("pubKey"), py::arg("data"));
	m.def("init", &init, "Initializes LibSodium. Repeated calls do nothing.");
	m.def("createECCKey", &createECCKey, "Create a new ECC private key");
	m.def("base64encode", &encode64, "Base 64 encode data with length.", py::arg("data"));
	m.def("base64decode", &decode64, "Base 64 decode data with length.", py::arg("data"));
	m.def("genOTP", &genOTP, "Create a random PIN/OTP");
	m.def("sleepOutOfGIL", &sleepOutOfGIL, "Sleep for specified seconds while releasing the GIL.", py::arg("seconds") = 5);
}