// Cross-PlatformCryptoLib.cpp : Defines the entry point for the application.
//
#include "Cross-PlatformCryptoLib.h"

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <tuple>
#include <openssl/aes.h>


static std::tuple<char*, char> AESEncrypt(unsigned char* text, unsigned char* key) {
	int msglen = strlen((char*)text);
	unsigned char iv[8];

	RAND_bytes(iv, 8);
	unsigned char* out = new unsigned char[msglen];
	AES_KEY aes_key;
	AES_set_encrypt_key(key, 128, &aes_key);

	AES_cbc_encrypt(text, out, msglen, &aes_key, iv, AES_ENCRYPT);
	memset((void*)text, 0, strlen((const char*)text));
	memset((void*)key, 0, strlen((const char*)key));
	memset(&aes_key, 0, sizeof(aes_key));
	char* result = new char[msglen];
	memcpy(result, out, msglen);
	memset(out, 0, msglen);
	delete out;
	delete text;
	delete key;

	return { result, (char)iv };


}
static char* AESDecrypt(unsigned char* iv, unsigned char* key, unsigned char* ctext) {
	int msglen = strlen((char*)ctext);
	unsigned char* out = new unsigned char[msglen];
	AES_KEY aes_key;
	AES_cbc_encrypt(ctext, out, msglen, &aes_key, iv, AES_DECRYPT);
	memset((void*)ctext, 0, strlen((const char*)ctext));
	memset((void*)key, 0, strlen((const char*)key));
	memset(&aes_key, 0, sizeof(aes_key));
	memset(&iv, 0, sizeof(iv));
	char* result = new char[msglen];
	memcpy(result, out, msglen);
	memset(out, 0, msglen);
	return result;
}

extern "C" {
	__declspec(dllexport) PyObject* AesEncryptPy(char* textb, char* keyb) {

		std::tuple<char, char> a = AESEncrypt(textb, keyb);
		PyObject* tup = Py_BuildValue("(yy)", std::get<0>(a), std::get<1>(a));
		memset(textb, 0, strlen(textb));
		memset(keyb, 0, strlen(keyb));
		delete keyb;
		delete textb;
		delete& a;

		return tup;


	}
	__declspec(dllexport) PyObject* AesDecryptPy(char* iv, char* key, char* ctext) {
		/*
		char* ctext = PyBytes_AsString(&ctextb);
		char* key = PyBytes_AsString(&keyb);
		char* iv = PyBytes_AsString(&ivb);
		*/
		char* a = AESDecrypt(iv, key, ctext);  //We believe it is unecesary to delete arguments passed inside functions as it is passed as reference
		memset(key, 0, strlen(key));
		PyObject* result = Py_BuildValue("y", a);
		memset(a, 0, strlen(a));
		delete ctext;
		delete key;
		delete iv;
		delete a;
		return result;
	}

	__declspec(dllexport) void Init() {
		Py_Initialize();
		//Initialize();
	}
}
