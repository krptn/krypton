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
#include <cmath>
#include <string>

extern "C" {
	DLLEXPORT unsigned char* __cdecl CAESEncrypt (unsigned char* texta, unsigned char* key, char* ivbuff) {
		int msglen = strlen((char*)texta);
		int rem = 16 - remainder(msglen, 16);
		unsigned char* text = new unsigned char[msglen + (long long)rem];
		memcpy_s(text, msglen + (long long)rem, texta, msglen);
		memset(text + msglen, 0, rem);
		OPENSSL_cleanse(texta, strlen((char*)texta));

		unsigned char iv[16];
		RAND_bytes(iv, 16);
		memcpy_s(ivbuff, 16, iv, 16);
		unsigned char* out = new unsigned char[msglen + (long long)rem];

		AES_KEY aes_key;
		AES_set_encrypt_key(key, 256, &aes_key);
		AES_cbc_encrypt(text, out, msglen + (long long)rem, &aes_key, iv, AES_ENCRYPT);

		OPENSSL_cleanse((void*)text, sizeof((const char*)text));
		OPENSSL_cleanse((void*)key, sizeof((const char*)key));
		OPENSSL_cleanse(&aes_key, sizeof(aes_key));
		/*
		memset(text,0,sizeof(text));
		memset(key,0,sizeof(key));
		memset(&aes_key,0,sizeof(aes_key));
		*/
		delete[] text;

		return out;
	}

	DLLEXPORT unsigned char* __cdecl CAESDecrypt(unsigned char* iv, unsigned char* key, unsigned char* ctexta) {
		int msglen = strlen((char*)ctexta);
		int rem = 16 - remainder(msglen, 16);
		unsigned char* ctext = new unsigned char[msglen + (long long)rem];
		memcpy_s(ctext, msglen, ctexta, msglen);
		memset(ctext + msglen, 0, rem);
		unsigned char* out = new unsigned char[msglen + (long long)rem];

		AES_KEY aes_key;
		AES_cbc_encrypt(ctext, out, msglen + (long long)rem, &aes_key, iv, AES_DECRYPT);
		OPENSSL_cleanse((void*)ctext, sizeof((const char*)ctext));
		OPENSSL_cleanse((void*)key, sizeof((const char*)key));
		OPENSSL_cleanse(&aes_key, sizeof(aes_key));
		OPENSSL_cleanse(&iv, sizeof(iv));
		delete[] ctext;
		return out;
	}


	DLLEXPORT int __cdecl Init() {
		Py_Initialize();

		if (FIPS_mode_set(2) == 0) {
			return 0;
		}
		return 1;
	}
}
std::initializer_list<std::string> AESEncrypt(char* textb, char* keyb) {
	char* iv = new char[8];
	char* a = (char*)CAESEncrypt((unsigned char*)textb, (unsigned char*)keyb, iv);
	OPENSSL_cleanse(textb, sizeof(textb));
	OPENSSL_cleanse(keyb, sizeof(keyb));
	auto result = { std::string(iv), std::string(a) };
	delete[] a;
	delete[] iv;
	return result;
}


std::string AESDecrypt(char* iv, char* key, char* ctext) {
	/*
	char* ctext = PyBytes_AsString(&ctextb);
	char* key = PyBytes_AsString(&keyb);
	char* iv = PyBytes_AsString(&ivb);
	*/
	char* a = (char*)CAESDecrypt((unsigned char*)iv, (unsigned char*)key, (unsigned char*)ctext);  //We believe it is unecesary to delete arguments passed inside functions as it is passed as reference
	OPENSSL_cleanse(key, strlen(key));
	std::string result = std::string(a);
	OPENSSL_cleanse(a, strlen(a));
	delete[] a;
	return result;
}
