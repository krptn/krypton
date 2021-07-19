// Cross-PlatformCryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#ifndef Win
#define DLLEXPORT
#endif
#ifdef Win
#define DLLEXPORT __declspec(dllexport)
#endif
#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <string.h>
#include <cmath>
#include <string>

// TODO: Reference additional headers your program requires here.
extern "C" {
	DLLEXPORT unsigned char* __cdecl CAESEncrypt(unsigned char* text, unsigned char* key, char* ivbuff);
	DLLEXPORT unsigned char* __cdecl CAESDecrypt(unsigned char* iv, unsigned char* key, unsigned char* ctext);
	DLLEXPORT int __cdecl Init();
}

std::initializer_list<std::string> AESEncrypt(char* textb, char* keyb);
std::string AESDecrypt(char* iv, char* key, char* ctext);

