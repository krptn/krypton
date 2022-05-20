// CryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <pybind11/pybind11.h>
#include <openssl/evp.h>
namespace py = pybind11;

// General 
int __cdecl AddToStrBuilder(char* buffer, char* content, int len, int Optionalstrlen);
unsigned char *decode64(const char *input, int length);
char *base64(const unsigned char *input, int length);
py::bytes py_decode64(const char *input, int length);
void handleErrors();

// AES
py::bytes __cdecl AESEncrypt(char* text, py::bytes key);
py::bytes __cdecl AESDecrypt(py::bytes ctext_b, py::bytes key);

//Hashes
int compHash(const void* a, const void* b, const size_t size);
char* __cdecl PBKDF2(char* text, char* salt, int iter);
py::bytes __cdecl pySHA512(char* text);

//ECC
std::tuple<py::bytes, py::bytes> __cdecl createECCKey();
py::bytes __cdecl getSharedKey(py::bytes privKey, py::bytes pubKey, py::bytes salt, int iter);
int getPubKey(EVP_PKEY *pkey, char* out);
int getPrivKey(EVP_PKEY *pkey, char* out);
int setPubKey(EVP_PKEY *pkey, char* key, int len);
int setPrivKey(EVP_PKEY *pkey, char* key, int len);
