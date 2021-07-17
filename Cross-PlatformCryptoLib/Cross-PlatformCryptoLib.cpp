// Cross-PlatformCryptoLib.cpp : Defines the entry point for the application.
//
#include "Cross-PlatformCryptoLib.h"

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <tuple>
#include <openssl/aes.h>
#include <string.h>


std::tuple<char*, char> AESEncrypt(unsigned char* text, unsigned char* key) {
	int msglen = strlen((char*)text);
	unsigned char iv[8];

	RAND_bytes(iv, 8);
	unsigned char* out = new unsigned char[msglen];
	AES_KEY aes_key;
	AES_set_encrypt_key(key, 128, &aes_key);

	AES_cbc_encrypt(text, out, msglen, &aes_key, iv, AES_ENCRYPT);
	OPENSSL_cleanse((void*)text, strlen((const char*)text));
	OPENSSL_cleanse((void*)key, strlen((const char*)key));
	OPENSSL_cleanse(&aes_key, sizeof(aes_key));
	char* result = new char[msglen];
	memcpy(result, out, msglen);
	OPENSSL_cleanse(out, msglen);
	delete out;
	delete text;
	delete key;

	return { result, (char)iv };


}
char* AESDecrypt(unsigned char* iv, unsigned char* key, unsigned char* ctext) {
	int msglen = strlen((char*)ctext);
	unsigned char* out = new unsigned char[msglen];
	AES_KEY aes_key;
	AES_cbc_encrypt(ctext, out, msglen, &aes_key, iv, AES_DECRYPT);
	OPENSSL_cleanse((void*)ctext, strlen((const char*)ctext));
	OPENSSL_cleanse((void*)key, strlen((const char*)key));
	OPENSSL_cleanse(&aes_key, sizeof(aes_key));
	OPENSSL_cleanse(&iv, sizeof(iv));
	char* result = new char[msglen];
	memcpy(result, out, msglen);
	OPENSSL_cleanse(out, msglen);
	return result;
}

PyObject* AESEncryptPy(char* textb, char* keyb) {

	std::tuple<char*, char> a = AESEncrypt((unsigned char*)textb, (unsigned char*)keyb);
	PyObject* tup = Py_BuildValue("(yy)", std::get<0>(a), std::get<1>(a));
	OPENSSL_cleanse(textb, strlen(textb));
	OPENSSL_cleanse(keyb, strlen(keyb));
	delete keyb;
	delete textb;
	delete& a;

	return tup;
}


PyObject* AESDecryptPy(char* iv, char* key, char* ctext) {
	/*
	char* ctext = PyBytes_AsString(&ctextb);
	char* key = PyBytes_AsString(&keyb);
	char* iv = PyBytes_AsString(&ivb);
	*/
	char* a = AESDecrypt((unsigned char*)iv, (unsigned char*)key, (unsigned char*)ctext);  //We believe it is unecesary to delete arguments passed inside functions as it is passed as reference
	OPENSSL_cleanse(key, strlen(key));
	PyObject* result = Py_BuildValue("y", a);
	OPENSSL_cleanse(a, strlen(a));
	delete ctext;
	delete key;
	delete iv;
	delete a;
	return result;
}

void Init() {
	Py_Initialize();
	//Initialize();
}
