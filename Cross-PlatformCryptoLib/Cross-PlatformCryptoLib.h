// Cross-PlatformCryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <tuple>
#include <Python.h>
// TODO: Reference additional headers your program requires here.

std::tuple<char*, char> AESEncrypt(unsigned char* text, unsigned char* key);
char* AESDecrypt(unsigned char* iv, unsigned char* key, unsigned char* ctext);

PyObject* AESEncryptPy(char* textb, char* keyb);
PyObject* AESDecryptPy(char* iv, char* key, char* ctext);

