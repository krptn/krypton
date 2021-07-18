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

// TODO: Reference additional headers your program requires here.
extern "C" {
	DLLEXPORT unsigned char* __cdecl AESEncrypt(unsigned char* text, unsigned char* key, char* ivbuff);
	DLLEXPORT unsigned char* __cdecl AESDecrypt(unsigned char* iv, unsigned char* key, unsigned char* ctext);
	DLLEXPORT PyObject* __cdecl AESEncryptPy(char* textb, char* keyb);
	DLLEXPORT PyObject* __cdecl AESDecryptPy(char* iv, char* key, char* ctext);
	DLLEXPORT int __cdecl Init();
}
