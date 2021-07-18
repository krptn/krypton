// Cross-PlatformCryptoLib.cpp : Defines the entry point for the application.

#include "Cross-PlatformCryptoLib.h"
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

extern "C" {
	DLLEXPORT unsigned char* __cdecl AESEncrypt(unsigned char* text, unsigned char* key, char* ivbuff) {
		int msglen = strlen((char*)text);
		unsigned char iv[16];
		RAND_bytes(iv,16);

		unsigned char* out = new unsigned char[msglen];

		AES_KEY aes_key;
		AES_set_encrypt_key(key, 256, &aes_key);
		int one = 1;
		AES_cbc_encrypt(text, out, msglen, &aes_key, iv, AES_ENCRYPT);

		OPENSSL_cleanse((void*)text, sizeof((const char*)text));
		OPENSSL_cleanse((void*)key, sizeof((const char*)key));
		OPENSSL_cleanse(&aes_key, sizeof(aes_key));
		/*
		memset(text,0,sizeof(text));
		memset(key,0,sizeof(key));
		memset(&aes_key,0,sizeof(aes_key));
		*/
		ivbuff = (char*)iv;
		return out;
	}

	DLLEXPORT unsigned char* __cdecl AESDecrypt(unsigned char* iv, unsigned char* key, unsigned char* ctext) {
		int msglen = sizeof((char*)ctext);
		unsigned char* out = new unsigned char[msglen];
		AES_KEY aes_key;
		AES_cbc_encrypt(ctext, out, msglen, &aes_key, iv, AES_DECRYPT);
		OPENSSL_cleanse((void*)ctext, sizeof((const char*)ctext));
		OPENSSL_cleanse((void*)key, sizeof((const char*)key));
		OPENSSL_cleanse(&aes_key, sizeof(aes_key));
		OPENSSL_cleanse(&iv, sizeof(iv));
		return out;
	}

	DLLEXPORT PyObject* __cdecl AESEncryptPy(char* textb, char* keyb) {
		char* iv = new char[8];
		char* a = (char*)AESEncrypt((unsigned char*)textb, (unsigned char*)keyb, iv);
		PyObject* tup = Py_BuildValue("(yy)", a,iv );
		OPENSSL_cleanse(textb, sizeof(textb));
		OPENSSL_cleanse(keyb, sizeof(keyb));
		delete[] a;
		delete[] iv;

		return tup;
	}


	DLLEXPORT PyObject* __cdecl AESDecryptPy(char* iv, char* key, char* ctext) {
		/*
		char* ctext = PyBytes_AsString(&ctextb);
		char* key = PyBytes_AsString(&keyb);
		char* iv = PyBytes_AsString(&ivb);
		*/
		char* a = (char*)AESDecrypt((unsigned char*)iv, (unsigned char*)key, (unsigned char*)ctext);  //We believe it is unecesary to delete arguments passed inside functions as it is passed as reference
		OPENSSL_cleanse(key, strlen(key));
		PyObject* result = Py_BuildValue("y", a);
		OPENSSL_cleanse(a, strlen(a));
		delete[] a;

		return result;
	}

	DLLEXPORT int __cdecl Init() {
		Py_Initialize();

		if (FIPS_mode_set(2) == 0) {
			return 0;
		}
		return 1;
	}
}

