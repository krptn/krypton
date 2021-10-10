// Cross-PlatformCryptoLib.cpp : Defines the entry point for the application.
// -fdeclspec -cfguard" for ninja buildArgs
#include "CryptoLib.h"
#define _CRT_SECURE_DEPRECATE_MEMORY
#ifndef Win
#define DLLEXPORT
#endif
#ifdef Win
//#define DLLEXPORT __declspec(dllexport)
#define DLLEXPORT
#endif
//#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <C:\Users\markb\VEnvs\PySecEnv\Lib\site-packages\pybind11\include/pybind11/pybind11.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>
using namespace std;
using namespace pybind11::literals;

struct NonNative {
	unsigned char* data;
	int len;
	bool str;
};

void handleErrors(int* err) {
	//Add to log here
	*err = *err + 1;
}

DLLEXPORT int __cdecl AddToStrBuilder(char* buffer, char* content, int len, int Optionalstrlen = 0) {
	int lena;
	if (Optionalstrlen == 0) {
		lena = strlen(content);
	}
	else {
		lena = Optionalstrlen;
	}
	memcpy_s(buffer + len, lena, content, lena);
	return 0;
}

DLLEXPORT unsigned char* __cdecl AESDecrypt(unsigned char* ctext, unsigned char* key, bool del = true) {
	char len_str[13];
	/*
OSSL_PROVIDER *fips;
OSSL_PROVIDER *base;
fips = OSSL_PROVIDER_load(NULL, "fips");
if (fips == NULL) {
printf("Failed to load FIPS provider\n");
exit(EXIT_FAILURE);
}
base = OSSL_PROVIDER_load(NULL, "base");
if (base == NULL) {
OSSL_PROVIDER_unload(fips);
printf("Failed to load base provider\n");
exit(EXIT_FAILURE);
}
*/
	memcpy_s(len_str, 12, ctext + (strnlen((char*)ctext, 549755813632) - 12), 12);
	len_str[12] = '\0';
	string str_lena = string(len_str);
	int flen = stoi(str_lena);
	int errcnt = 0;
	int leny = strlen((char*)ctext);
	int msglen = strlen((char*)ctext) - 12 - 16 - 12;
	auto msg = unique_ptr<unsigned char[]>(new unsigned char[msglen]);
	//unsigned char* msg = new unsigned char[msglen];
	memcpy_s(msg.get(), msglen, ctext, msglen);
	unsigned char iv[12];
	memcpy_s(iv, 12, ctext + msglen + 16, 12);
	unsigned char tag[16];
	memcpy_s(tag, 16, ctext + msglen, 16);

	/*
	unsigned char* ctext = new unsigned char[msglen];
	memcpy(ctext, ctexta, msglen);
	*/
	auto out = unique_ptr<unsigned char[]>(new unsigned char[msglen + (long long)1]);
	//unsigned char* out = new unsigned char[msglen];
	EVP_CIPHER_CTX* ctx;
	int len;
	int plaintext_len;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors(&errcnt);
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors(&errcnt);
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
		handleErrors(&errcnt);
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		handleErrors(&errcnt);
	if (1 != EVP_DecryptUpdate(ctx, out.get(), &len, msg.get(), msglen))
		handleErrors(&errcnt);
	plaintext_len = len;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		handleErrors(&errcnt);
	delete[] msg.release();
	int ret = EVP_DecryptFinal_ex(ctx, out.get() + len, &len);
	plaintext_len += len;
	if (del == true) {
		OPENSSL_cleanse(key, 32);
	}
	EVP_CIPHER_CTX_free(ctx);
	if ((!(ret >= 0)) || (errcnt > 0)) {
		unsigned char error[] = "Error: Crypto-Error: Unable to decrypt data";
		return error;
	}
	/*
	OSSL_PROVIDER_unload(base);
	OSSL_PROVIDER_unload(fips);
	*/
	out[flen] = '\0';
	return out.release();
}

DLLEXPORT unsigned char* __cdecl AESEncrypt(unsigned char* text, unsigned char* key, bool del = true) {
	if (strlen((char*)text) > 549755813632) {
		unsigned char error[] = "Error: The data is too long";
		return error;
	}
	unsigned char ivbuff[12];
	unsigned char tag[16];
	/*
	OSSL_PROVIDER *fips;
	OSSL_PROVIDER *base;
	fips = OSSL_PROVIDER_load(NULL, "fips");
	if (fips == NULL) {
	printf("Failed to load FIPS provider\n");
	}
	base = OSSL_PROVIDER_load(NULL, "base");
	if (base == NULL) {
	OSSL_PROVIDER_unload(fips);
	printf("Failed to load base provider\n");
	}
	*/
	int errcnt = 0;
	int msglen = strnlen((char*)text, 549755813632);

	int rem = 16 - (msglen % 16);
	/*
	unsigned char* text = new unsigned char[msglen+(long long)rem];
	memcpy_s(text, msglen, texta, msglen);
	memset(text + msglen, 0, rem);
	OPENSSL_cleanse(texta,msglen);
	*/
	unsigned char iv[12];
	RAND_bytes(iv, 12);
	memcpy_s(&ivbuff, 12, iv, 12);
	auto out = unique_ptr<unsigned char[]>(new unsigned char[msglen + (long long)rem + (long long)1]);
	//unsigned char* out = new unsigned char[msglen+(long long)rem+(long long)1];
	EVP_CIPHER_CTX* ctx;
	int len;
	int ciphertext_len;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors(&errcnt);
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors(&errcnt);
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
		handleErrors(&errcnt);
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
		handleErrors(&errcnt);
	if (1 != EVP_EncryptUpdate(ctx, out.get(), &len, text, msglen))
		handleErrors(&errcnt);
	ciphertext_len = len;

	if (1 != EVP_EncryptFinal_ex(ctx, out.get() + len, &len))
		handleErrors(&errcnt);

	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, &tag))
		handleErrors(&errcnt);
	ciphertext_len += len;
	if (del == true) {
		OPENSSL_cleanse(key, 32);
		OPENSSL_cleanse(text, msglen);
	}
	EVP_CIPHER_CTX_free(ctx);
	if (errcnt != 0) {
		unsigned char error[] = "Error: Crypto Error";
		return error;
	}
	auto result = unique_ptr<unsigned char[]>(new unsigned char[ciphertext_len + (long long)16 + (long long)12 + (long long)1 + (long long)12]);
	//unsigned char* result = new unsigned char[ciphertext_len+(long long)16+ (long long)12+(long long)1];
	AddToStrBuilder((char*)result.get(), (char*)out.get(), 0, ciphertext_len);
	delete[] out.release();
	AddToStrBuilder((char*)result.get(), (char*)&tag, ciphertext_len, 16);
	AddToStrBuilder((char*)result.get(), (char*)&iv, ciphertext_len + 16, 12);
	unsigned char len_num[12];
	string num = to_string(msglen);
	int ler = num.length();
	const char* num_len = num.c_str();
	AddToStrBuilder((char*)result.get(), (char*)num_len, ciphertext_len + 12 + 16 + (12 - ler), ler);
	memset(result.get() + ciphertext_len + 12 + 16, '0', ((long long)12 - ler));

	/*
	OSSL_PROVIDER_unload(base);
	OSSL_PROVIDER_unload(fips);
	*/
	result[ciphertext_len + (long long)16 + (long long)12 + (long long)12] = '\0';

	return result.release();
}

/*
DLLEXPORT NonNative __cdecl NonNativeAESEncrypt(unsigned char* ctext, unsigned char* key) {
	unsigned char* ret = AESEncrypt(ctext, key, true);
	NonNative result;
	result.data = ret;
	result.len = strlen((const char*)ret);
	result.str = true;
	return result;
}

DLLEXPORT unsigned char* __cdecl NonNativeAESDecrypt(NonNative ctext, unsigned char* key) {
	int lena;
	if (ctext.str) {
		lena = strlen((const char*)ctext.data);
	}
	else {
		lena = ctext.len;
	}
	auto text = unique_ptr<unsigned char[]>(new unsigned char[lena + (long long)1]);
	memcpy_s(text.get(), lena, ctext.data, lena);
	text[lena] = '\0';
	int len;
	unsigned char* ret = AESDecrypt(text.get(), key, true, &len);
	//ret[len] = '\0';
	return ret;
}

DLLEXPORT int test(unsigned char* ctext, unsigned char* key) {
	int len = strlen((const char*)ctext);
	auto key_b = unique_ptr<unsigned char[]>(new unsigned char[33]);
	auto ctext_b = unique_ptr<unsigned char[]>(new unsigned char[strnlen((const char*)ctext, 10) + (long long)1]);
	ctext_b[len] = '\0';
	auto ctext_c = unique_ptr<unsigned char[]>(new unsigned char[strnlen((const char*)ctext, 10) + (long long)1]);
	ctext_c[len] = '\0';
	memcpy_s(key_b.get(), 32, key, 32);
	key_b[32] = '\0';
	memcpy_s(ctext_b.get(), strnlen((const char*)ctext, 10), ctext, strnlen((const char*)ctext, 10));
	memcpy_s(ctext_c.get(), strnlen((const char*)ctext, 10), ctext, strnlen((const char*)ctext, 10));
	NonNative text_a = NonNativeAESEncrypt(ctext_b.get(), key);
	unsigned char* text_b = NonNativeAESDecrypt(text_a, key_b.get());
	if (*text_b == *ctext) {
		return 1;
	}
	else {
		return 0;
	}
}
*/

//Libs for C++ code
namespace Cpp {
	std::string EncryptAES(std::string textb, std::string keyb) {
		unsigned char* text = (unsigned char*)textb.c_str();
		unsigned char* key = (unsigned char*)keyb.c_str();
		unsigned char* a = AESEncrypt(text, key, true);
		delete[] key;
		delete[] text;
		auto result = std::string((char*)a);
		delete[] a;
		return result;
	}


	std::string DecryptAES(std::string key, std::string ctext) {
		unsigned char* keyc = (unsigned char*)key.c_str();
		unsigned char* ctextc = (unsigned char*)ctext.c_str();
		unsigned char* a = AESDecrypt(keyc, ctextc, true);
		delete[] keyc;
		delete[] ctextc;
		std::string result = std::string((char*)a);
		OPENSSL_cleanse(a, strnlen((const char*)a, 549755813632));
		delete[] a;
		return result;
	}
}

extern "C" DLLEXPORT int __cdecl Init() {
	//EVP_set_default_properties(NULL, "fips=yes");
	EVP_add_cipher(EVP_aes_256_gcm());
	if (FIPS_mode_set(2) == 0) {
		return 0;
	}
	return 1;
};

namespace py = pybind11;
PYBIND11_PLUGIN(CryptoLib) {
	py::module m("CryptoLib", "PySec crypto component.");
	m.def("Decrypt", &AESDecrypt, "A function which decrypts the data. Args: text, key.");

	m.def("Encrypt", &AESEncrypt, "A function which encrypts the data. Args: text, key.");
	return m.ptr();
}
