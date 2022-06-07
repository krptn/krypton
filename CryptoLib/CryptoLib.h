// CryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once
#define OPENSSL_NO_DEPRECATED
#define __STDC_WANT_LIB_EXT1__ 1

#include <pybind11/pybind11.h>
#include <openssl/evp.h>

namespace py = pybind11;

// General
unsigned char *decode64(char* input, int length);
char* base64(char* data, int length);
py::bytes py_decode64(const char* input, int length);
void handleErrors();
char* pymbToBuffer(py::bytes a);
char* pyStrToBuffer(py::str a);

// AES
py::bytes AESEncrypt(char* textc, py::bytes key, int msglenc);
py::bytes AESDecrypt(py::bytes ctext_b, py::bytes key);

// Hashes
int compHash(const void* a, const void* b, const size_t size);
char* PBKDF2(char* text, int len, char* salt, int iter, int saltLen, int keylen=32);
py::bytes pyPBKDF2(char* text, int len, char* salt, int iter, int saltLen, int keylen=32);

// ECC
py::tuple createECCKey();
py::bytes getSharedKey(py::str privKey, py::str pubKey, py::bytes salt, int iter, int keylen);
int getPubKey(EVP_PKEY *pkey, char* out);
int getPrivKey(EVP_PKEY *pkey, char* out);
int setPubKey(EVP_PKEY **pkey, char* key, int len);
int setPrivKey(EVP_PKEY **pkey, char* key, int len);
