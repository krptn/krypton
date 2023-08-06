// CryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <pybind11/pybind11.h>
#include <string>

namespace py = pybind11;

// General
py::str encode64(std::string data);
py::bytes decode64(std::string input);

// Symmetric
py::bytes encryptWithSecret(std::string text, std::string key);
py::bytes decryptWithSecret(std::string ctext, std::string key);

// Hashes
int compHash(char *a, char *b, const size_t size);
py::bytes passwordHash(std::string text, std::string salt, int opsLimit, int memLimit, int keylen);

// ECC
py::tuple createECCKey();
py::bytes encryptEcc(std::string privKey, std::string pubKey, std::string data);
py::bytes decryptEcc(std::string privKey, std::string pubKey, std::string data);

// OTPs
py::str genOTP();
bool sleepOutOfGIL(int seconds = 5);
