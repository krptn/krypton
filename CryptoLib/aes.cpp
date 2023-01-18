#include "CryptoLib.h"

#include <pybind11/pybind11.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

using namespace std;
namespace py = pybind11;

const int AES_KEY_LEN = 32;
const int IV_SALT_LEN = 12;
const int AUTH_TAG_LEN = 16;
const auto AES_ALGO = EVP_aes_256_gcm;

py::bytes AESEncrypt(char* textc, py::bytes key, int msglenc) {
	if (key.attr("__len__")().cast<int>() != AES_KEY_LEN) {
		throw std::invalid_argument("Key is of wrong size");
	}
	int msglen = msglenc + 4;
	char* text = new char[msglen];
	memcpy(text + 4, textc, msglenc);
	text[0] = '$';
	text[1] = 'C';
	text[2] = 'r';
	text[3] = msglenc;
	char* k = pymbToBuffer(key);
	int rem = AUTH_TAG_LEN - (msglen % AUTH_TAG_LEN);
	int flen = msglen + (long long)rem + (long long)AUTH_TAG_LEN + (long long)IV_SALT_LEN;
	auto out = unique_ptr<unsigned char[]>(new unsigned char[flen]);
	unsigned char* iv = out.get() + flen - (long long)IV_SALT_LEN;
	if (!(RAND_bytes(iv, IV_SALT_LEN) == 1))
		handleErrors();
	unsigned char* tag = out.get() + flen - (long long)IV_SALT_LEN - (long long)AUTH_TAG_LEN;

	EVP_CIPHER_CTX* ctx;
	int len;
	int ciphertext_len;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
	if (1 != EVP_EncryptInit_ex(ctx, AES_ALGO(), NULL, NULL, NULL))
		handleErrors();
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SALT_LEN, NULL))
		handleErrors();
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char*)k, iv))
		handleErrors();
	if (1 != EVP_EncryptUpdate(ctx, out.get(), &len, (unsigned char*)text, msglen))
		handleErrors();
	ciphertext_len = len;
	if (1 != EVP_EncryptFinal_ex(ctx, out.get() + len, &len))
		handleErrors();
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LEN, tag))
		handleErrors();
	ciphertext_len += len;
	int fflen = ciphertext_len + (long long)AUTH_TAG_LEN + (long long)IV_SALT_LEN;
	auto finalOut = unique_ptr<unsigned char[]>(new unsigned char[fflen]);
	memcpy(finalOut.get(), out.get(), ciphertext_len);
	memcpy(finalOut.get() + flen - IV_SALT_LEN - AUTH_TAG_LEN, out.get() + ciphertext_len, IV_SALT_LEN + AUTH_TAG_LEN);
	OPENSSL_cleanse(text, msglen);
	OPENSSL_cleanse(k, 32);
	EVP_CIPHER_CTX_free(ctx);
	py::bytes bresult = py::bytes((const char*)finalOut.get(), fflen);
	delete[] text;
	delete[] k;
	return bresult;
}

py::bytes AESDecrypt(py::bytes ctext_b, py::bytes key){
	if (key.attr("__len__")().cast<int>() != AES_KEY_LEN){
		throw std::invalid_argument("Key is of wrong size");
	}
	int input_len = ctext_b.attr("__len__")().cast<int>();
	char* b = pymbToBuffer(ctext_b);
	char* k = pymbToBuffer(key);
	int msglen = input_len - AUTH_TAG_LEN - IV_SALT_LEN;
	auto out = unique_ptr<unsigned char[]>(new unsigned char[msglen]);
	unsigned char* iv = (unsigned char*)b + input_len - IV_SALT_LEN;
	unsigned char* tag = (unsigned char*)b + msglen;
	EVP_CIPHER_CTX* ctx;
	int len = 0;
	int plaintext_len = 0;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
	if (!EVP_DecryptInit_ex(ctx, AES_ALGO(), NULL, NULL, NULL))
		handleErrors();
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SALT_LEN, NULL))
		handleErrors();
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char*)k, iv))
		handleErrors();
	if (1 != EVP_DecryptUpdate(ctx, out.get(), &len, (const unsigned char*)b, msglen))
		handleErrors();
	plaintext_len = len;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AUTH_TAG_LEN, tag))
		handleErrors();
	int ret = EVP_DecryptFinal_ex(ctx, out.get() + len, &len);
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	OPENSSL_cleanse(k, AES_KEY_LEN);
	if (!(ret >= 0)) {
		throw std::invalid_argument("Unable to decrypt ciphertext");
	}
	int plainMsgLen = out.get()[3];
	if (out.get()[0] != '$' || out.get()[1] != 'C' || out.get()[2] != 'r') {
		throw std::invalid_argument("Unable to decrypt ciphertext");
	}
	delete[] b;
	delete[] k;
	py::bytes bytes = py::bytes((char*)out.get() + 4, plaintext_len);
	OPENSSL_cleanse(out.get(), msglen);
	return bytes;
}
