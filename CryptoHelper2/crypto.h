#pragma once
#include <python.h>
#include <tuple>
#include "aes.h"
static char* AESDecrypt(char* iv, char* key, char* ctext);
static std::tuple<char, char> AESEncrypt(char* text, char* key);

extern "C" {
	__declspec(dllexport) PyObject* AesEncryptPy(char* textb, char* keyb);
	__declspec(dllexport) PyObject* AesDecryptPy(PyObject ivb, PyObject keyb, PyObject ctextb);
	__declspec(dllexport) void Init();
}

