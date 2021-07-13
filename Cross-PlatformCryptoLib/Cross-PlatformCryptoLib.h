// Cross-PlatformCryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <iostream>


// TODO: Reference additional headers your program requires here.

static std::tuple<char*, char> AESEncrypt(unsigned char* text, unsigned char* key);
static char* AESDecrypt(unsigned char* iv, unsigned char* key, unsigned char* ctext);

extern "C" {
	__declspec(dllexport) PyObject* AesEncryptPy(char* textb, char* keyb);
	__declspec(dllexport) PyObject* AesDecryptPy(char* iv, char* key, char* ctext);
	__declspec(dllexport) void Init();
}
