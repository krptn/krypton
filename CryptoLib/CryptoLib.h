// CryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <pybind11/pybind11.h>

namespace py = pybind11;

// General
py::str encode64(std::string data);
py::bytes decode64(std::string input);

// AES
py::bytes encrypt(std::string text, std::string key);
py::bytes decrypt(std::string ctext, std::string key);

// Hashes
int compHash(const void *a, const void *b, const size_t size);
py::bytes passwordHash(std::string text, std::string salt, int opsLimit, int memLimit, int keylen);

// ECC
py::tuple createECCKey();
py::bytes encryptEcc(std::string privKey, std::string pubKey, std::string data);
py::bytes decryptEcc(std::string privKey, std::string pubKey, std::string data);

// OTPs
py::str genOTP();
bool sleepOutOfGIL(int seconds = 5);
