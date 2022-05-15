// CryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <pybind11/pybind11.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
 #include <openssl/encoder.h>
namespace py = pybind11;

int __cdecl AddToStrBuilder(char* buffer, char* content, int len, int Optionalstrlen);
py::bytes __cdecl AESEncrypt(char* text, py::bytes key);
py::bytes __cdecl AESDecrypt(py::bytes ctext_b, py::bytes key);
char* __cdecl HASH_FOR_STORAGE(char* text);
int compHash(const void* a, const void* b, const size_t size);
py::bytes __cdecl Auth(char* pwd, char* stored_HASH);
py::bytes __cdecl getKeyFromPass(char* pwd);
std::tuple<py::bytes, py::bytes> __cdecl createECCKey();
py::bytes __cdecl getSharedKey(py::bytes privKey, py::bytes pubKey);
unsigned char *decode64(const char *input, int length);
char *base64(const unsigned char *input, int length);
py::bytes py_decode64(const char *input, int length),
void handleErrors();
int getPubKey(EVP_PKEY *pkey);
int getPrivKey(EVP_PKEY *pkey);
int setPubKey(char* pkey);
int setPrivKey(char* pkey);
