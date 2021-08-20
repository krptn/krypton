// Cross-PlatformCryptoLib.cpp : Defines the entry point for the application.
// -fdeclspec -cfguard" for ninja buildArgs
#include "CryptoLib.h"
#ifndef Win
#define DLLEXPORT
#endif
#ifdef Win
#define DLLEXPORT __declspec(dllexport)
#endif
//#define PY_SSIZE_T_CLEAN

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <cmath>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>
using namespace std;

struct NonNative {
	unsigned char* data;
	int len;
};

extern "C" {
	void handleErrors(int* err) {
		//Add to log here
		*err = *err + 1;
	}
	DLLEXPORT int __cdecl AddToStrBuilder(char* buffer, char* content, int len) {
		memcpy_s(buffer + len, strlen(content), content, strlen(content));
		return 0;
	}

	DLLEXPORT unsigned char* __cdecl AESEncrypt(unsigned char* text, unsigned char* key, bool del) {
		try {
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
			int msglen = strlen((char*)text);

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
			unique_ptr<unsigned char[]> out(new unsigned char[msglen + (long long)rem + (long long)1]);
			//unsigned char* out = new unsigned char[msglen+(long long)rem+(long long)1];
			EVP_CIPHER_CTX* ctx;
			int len;
			int ciphertext_len;
			if (!(ctx = EVP_CIPHER_CTX_new()))
				handleErrors(&errcnt);
			if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
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
				OPENSSL_cleanse(key, strnlen((const char*)key, 32));
				OPENSSL_cleanse(text, msglen);
			}
			EVP_CIPHER_CTX_free(ctx);
			text[msglen] = '/0';
			key[31] = '/0';
			if (errcnt != 0) {
				unsigned char error[] = "Error: Crypto Error";
				return error;
			}
			unique_ptr<unsigned char[]> result(new unsigned char[ciphertext_len + (long long)16 + (long long)12 + (long long)1]);
			//unsigned char* result = new unsigned char[ciphertext_len+(long long)16+ (long long)12+(long long)1];
			AddToStrBuilder((char*)result.get(), (char*)out.get(), 0);
			delete[] out.release();
			AddToStrBuilder((char*)result.get(), (char*)&tag, ciphertext_len);
			AddToStrBuilder((char*)result.get(), (char*)&iv, ciphertext_len + 16);
			/*
			OSSL_PROVIDER_unload(base);
			OSSL_PROVIDER_unload(fips);
			*/
			result[ciphertext_len + (long long)16 + (long long)12] = '/0';
			return result.release();
		}
		catch (...) {
			unsigned char error[] = "Error: Non-Crypto error";
			return error;
		}
	}

	DLLEXPORT unsigned char* __cdecl AESDecrypt(unsigned char* ctext, unsigned char* key, bool del) {
		try {
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
			int errcnt = 0;
			int leny = strlen((char*)ctext);
			int msglen = strlen((char*)ctext) - 12 - 12 - 16;
			unique_ptr<unsigned char[]> msg(new unsigned char[msglen]);
			//unsigned char* msg = new unsigned char[msglen];
			memcpy_s(msg.get(), msglen, ctext, msglen);
			unsigned char iv[12];
			memcpy_s(iv, 12, ctext + msglen + 16 - 1, 12);
			unsigned char tag[16];
			memcpy_s(tag, 16, ctext + msglen - 1, 16);
			delete[] ctext;
			/*
			unsigned char* ctext = new unsigned char[msglen];
			memcpy(ctext, ctexta, msglen);
			*/
			unique_ptr<unsigned char[]> out(new unsigned char[msglen]);
			//unsigned char* out = new unsigned char[msglen];
			EVP_CIPHER_CTX* ctx;
			int len;
			int plaintext_len;
			if (!(ctx = EVP_CIPHER_CTX_new()))
				handleErrors(&errcnt);
			if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
				handleErrors(&errcnt);
			if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
				handleErrors(&errcnt);
			if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
				handleErrors(&errcnt);
			if (1 != EVP_DecryptUpdate(ctx, out.get(), &len, msg.get(), msglen))
				handleErrors(&errcnt);
			plaintext_len = len;
			int ret = EVP_DecryptFinal_ex(ctx, out.get() + len, &len);
			plaintext_len += len;
			if (del == true) {
				OPENSSL_cleanse(key, strnlen((const char*)key, 32));
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
			unsigned char* result = new unsigned char[plaintext_len + (long long)1];
			memcpy_s(result, strnlen((const char*)out.get(), plaintext_len), out.get(), strnlen((const char*)out.get(), plaintext_len));
			OPENSSL_cleanse(out.get(), msglen);
			result[plaintext_len] = '/0';
			return result;
		}
		catch (...) {
			unsigned char error[] = "Error: Non-Crypto error";
			return error;
		}
	}
	DLLEXPORT NonNative __cdecl NonNativeAESEncrypt(unsigned char* ctext, unsigned char* key) {
		unsigned char* ret = AESEncrypt(ctext, key, true);
		NonNative result;
		result.data = ret;
		result.len = strlen((const char*)ret);
		return result;
	}
	DLLEXPORT unsigned char* __cdecl NonNativeAESDecrypt(NonNative ctext, unsigned char* key) {
		unsigned char* text = new unsigned char[ctext.len];
		memcpy_s(text, ctext.len, ctext.data, ctext.len);
		unsigned char* ret = AESDecrypt(text, key, true);
		return ret;
	}
}

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
