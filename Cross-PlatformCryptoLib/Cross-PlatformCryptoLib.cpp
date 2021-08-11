// Cross-PlatformCryptoLib.cpp : Defines the entry point for the application.
// -fdeclspec -cfguard" for ninja buildArgs
#include "Cross-PlatformCryptoLib.h"
#ifndef Win
#define DLLEXPORT
#endif
#ifdef Win
#define DLLEXPORT __declspec(dllexport)
#endif
#define PY_SSIZE_T_CLEAN

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string.h>
#include <cmath>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

extern "C" {

	void handleErrors(int* err) {
		//Add to log here
		*err = *err + 1;
	}
	DLLEXPORT int __cdecl AddToStrBuilder(char* buffer,char* content, int len) {
		memcpy_s(buffer + len, strlen(content), content, strlen(content));
		return 0;
	}

	DLLEXPORT unsigned char* __cdecl AESEncrypt(unsigned char* text, unsigned char* key, bool del) {
		try{
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
			
		int rem = 16 - remainder(msglen, 16);
		/*
		unsigned char* text = new unsigned char[msglen+(long long)rem];
		memcpy_s(text, msglen, texta, msglen);
		memset(text + msglen, 0, rem);
		OPENSSL_cleanse(texta,msglen);
		*/
		unsigned char iv[12];
		RAND_bytes(iv, 12);
		memcpy_s(&ivbuff, 12, iv, 12);
		unsigned char* out = new unsigned char[msglen+(long long)rem+(long long)1];
		/*
		AES_KEY aes_key;
		AES_set_encrypt_key(key, 256, &aes_key);
		AES_cbc_encrypt(text, out, msglen + (long long)rem, &aes_key, iv, AES_ENCRYPT);

		OPENSSL_cleanse((void*)text, sizeof((const char*)text));
		OPENSSL_cleanse((void*)key, sizeof((const char*)key));
		OPENSSL_cleanse(&aes_key, sizeof(aes_key));
		delete[] text;

		return out;
		*/
		EVP_CIPHER_CTX* ctx;
		int len;
		int ciphertext_len;
		if (!(ctx = EVP_CIPHER_CTX_new()))
			handleErrors(&errcnt);
		if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
			handleErrors(&errcnt);
		//EVP_CIPHER_CTX_set_padding(ctx, 0);
		if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
			handleErrors(&errcnt);
		if (1 != EVP_EncryptUpdate(ctx, out, &len, text, msglen))
			handleErrors(&errcnt);
		ciphertext_len = len;

		if (1 != EVP_EncryptFinal_ex(ctx, out + len, &len))
			handleErrors(&errcnt);

		if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, &tag))
			handleErrors(&errcnt);
		ciphertext_len += len;
		if (del == true) {
			OPENSSL_cleanse(key,strnlen((const char*)key,32));
			OPENSSL_cleanse(text,msglen);
		}
		EVP_CIPHER_CTX_free(ctx);
		text[msglen] = '/0';
		key[31] = '/0';
		if (errcnt != 0) {
			unsigned char error[] = "Error: Crypto Error";
			return error;
		}
		unsigned char* result = new unsigned char[ciphertext_len+(long long)16+ (long long)12+(long long)12];
		AddToStrBuilder((char*)result, (char*)out,12);
		AddToStrBuilder((char*)result, (char*)&tag,12+ciphertext_len);
		AddToStrBuilder((char*)result, (char*)&iv, 12 + ciphertext_len+16);
		int i = 0;
		int u = 0;
		int msglena = msglen;
		int h = 0;
		while (msglena > 0)
		{
			msglena = msglena / 10;
			h++;
		}
		for (u; u < h;++u) {
			result[11-i] = '0'+ *(&msglen + u);
		}
		memset(result,48,(long long)12-h);
		/*
		OSSL_PROVIDER_unload(base);
		OSSL_PROVIDER_unload(fips);
		*/
		delete[] out;
		return result;
		}
		catch (...) {
			unsigned char error[] = "Error: Non-Crypto error";
			return error;
		}
	}

	DLLEXPORT unsigned char* __cdecl AESDecrypt(unsigned char* key ,unsigned char* ctext, bool del) {
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
			int msglen = strlen((char*)ctext) -12-12-16;
			int lena = 0;
			for (int i = 0; i < 12; ++i) {
				int len = (*(ctext-i+12)-'0');
				if (i == 0) {
					lena += len;
				}
				else {
					lena += len * i * 10;
				}
			}
			unsigned char* msg = new unsigned char[msglen];
			memcpy_s(msg, msglen, ctext + 12, msglen);
			unsigned char iv[12];
			memcpy_s(iv, 12, ctext + msglen + 12+16-1, 12);
			unsigned char tag[16];
			memcpy_s(tag, 16, ctext + 12 + msglen-1, 16);
			delete[] ctext;
			/*
			unsigned char* ctext = new unsigned char[msglen];
			memcpy(ctext, ctexta, msglen);
			*/
			unsigned char* out = new unsigned char[msglen];
			/*
			AES_KEY aes_key;
			AES_cbc_encrypt(ctext, out, msglen + (long long)rem, &aes_key, iv, AES_DECRYPT);
			*/
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
			if (1 != EVP_DecryptUpdate(ctx, out, &len, msg, msglen))
				handleErrors(&errcnt);
			delete[] msg;
			plaintext_len = len;
			int ret = EVP_DecryptFinal_ex(ctx, out + len, &len);
			plaintext_len += len;
			if (del == true){
				OPENSSL_cleanse(key,strnlen((const char*)key,32));
			}
			EVP_CIPHER_CTX_free(ctx);
			if ((!(ret >= 0))|| (errcnt > 0)) {
				unsigned char error[] = "Error: Crypto-Error: Unable to decrypt data";
				return error;
			}
			/*
			OSSL_PROVIDER_unload(base);
			OSSL_PROVIDER_unload(fips);
			*/
			unsigned char* result = new unsigned char[strnlen((const char*)out,plaintext_len)];
			memcpy_s(result, strnlen((const char*)out, plaintext_len),out, strnlen((const char*)out, plaintext_len));
			OPENSSL_cleanse(out,msglen);
			delete[] out;
			return result;
		}
		catch (...) {
			unsigned char error[] = "Error: Non-Crypto error";
			return error;
		}
	}
	
}

//Libs for C++ code
namespace Cpp {
	std::string EncryptAES(std::string textb, std::string keyb) {
		unsigned char* a = AESEncrypt((unsigned char*)textb.c_str(), (unsigned char*)keyb.c_str(),true);
		auto result = std::string((char*)a);
		delete[] a;
		return result;
	}


	std::string DecryptAES(std::string key, std::string ctext) {
		unsigned char* a = AESDecrypt((unsigned char*)key.c_str(), (unsigned char*)ctext.c_str(),true);  //We believe it is unecesary to delete arguments passed inside functions as it is passed as reference
		std::string result = std::string((char*)a);
		OPENSSL_cleanse(a,strnlen((const char*)a, 549755813632));
		delete[] a;
		return result;
	}
}

DLLEXPORT int __cdecl Init() {
	//EVP_set_default_properties(NULL, "fips=yes");
	EVP_add_cipher(EVP_aes_256_gcm());
	if (FIPS_mode_set(2) == 0) {
		return 0;
	}
	return 1;
};
