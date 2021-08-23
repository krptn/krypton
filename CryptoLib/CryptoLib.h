// CryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once
#define _CRT_SECURE_DEPRECATE_MEMORY
#ifndef Win
#define DLLEXPORT
#endif
#ifdef Win
#define DLLEXPORT __declspec(dllexport)
#endif
//#define PY_SSIZE_T_CLEAN

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>

// TODO: Reference additional headers your program requires here.

struct NonNative;

extern "C" {
	DLLEXPORT int __cdecl AddToStrBuilder(char* buffer, char* content, int len, int Optionalstrlen);
	DLLEXPORT unsigned char* __cdecl AESDecrypt(unsigned char* ctext, unsigned char* key, bool del);
	DLLEXPORT unsigned char* __cdecl AESEncrypt(unsigned char* text, unsigned char* key, bool del);
}

namespace Cpp {
	std::string EncryptAES(std::string textb, std::string keyb);
	std::string DecryptAES(std::string key, std::string ctext);
}

extern "C" DLLEXPORT int __cdecl Init();