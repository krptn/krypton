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
namespace py = pybind11;

int __cdecl AddToStrBuilder(char* buffer, char* content, int len, int Optionalstrlen);
py::bytes __cdecl AESDecrypt(char* ctext_b, char* key);
char* __cdecl AESEncrypt(char* text, char* key);
char* __cdecl HASH_FOR_STORAGE(char* text);
bool __cdecl HASHCompare(char* hash, char* text);
py::bytes __cdecl GetKeyFromPass(char* pwd, char* salt);
