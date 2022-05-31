// CryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once
#define OPENSSL_NO_DEPRECATED

#include <pybind11/pybind11.h>
#include <openssl/evp.h>

namespace py = pybind11;

// General 
int __cdecl AddToStrBuilder(char* buffer, char* content, int len, int Optionalstrlen);
unsigned char *decode64(char* input, int length);
char* base64(char* data, int length);
py::bytes py_decode64(const char* input, int length);
void handleErrors();
char* pymbToBuffer(py::bytes a);

// AES
py::bytes __cdecl AESEncrypt(char* textc, py::bytes key, int msglenc);
py::bytes __cdecl AESDecrypt(py::bytes ctext_b, py::bytes key);

// Hashes
int compHash(const void* a, const void* b, const size_t size);
char* __cdecl PBKDF2(char* text, int len, char* salt, int iter, int saltLen, int keylen=32);
py::bytes pyPBKDF2(char* text, int len, char* salt, int iter, int saltLen, int keylen=32);
py::bytes __cdecl pySHA512(py::bytes text);

// ECC
py::tuple __cdecl createECCKey();
py::bytes __cdecl getSharedKey(py::str privKey, py::str pubKey, py::bytes salt, int iter);
int getPubKey(EVP_PKEY *pkey, char* out);
int getPrivKey(EVP_PKEY *pkey, char* out);
int setPubKey(EVP_PKEY *pkey, char* key, int len);
int setPrivKey(EVP_PKEY *pkey, char* key, int len);
