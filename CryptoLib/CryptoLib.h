// CryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once
#define _CRT_SECURE_DEPRECATE_MEMORY

#include <pybind11/pybind11.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>

struct NonNative;

int __cdecl AddToStrBuilder(char* buffer, char* content, int len, int Optionalstrlen);
unsigned char* __cdecl AESDecrypt(unsigned char* ctext, unsigned  char* key,bool del);
unsigned char* __cdecl AESEncrypt(unsigned char* text, unsigned  char* key,bool del);

extern "C" int __cdecl Init();
