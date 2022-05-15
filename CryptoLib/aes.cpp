#include "CryptoLib.h"

#include <pybind11/pybind11.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

using namespace std;
namespace py = pybind11;

int MAX_CRYPTO_LEN = 549755813632;
const int AES_KEY_LEN = 32;
const int IV_SALT_LEN = 12;
const int AUTH_TAG_LEN = 16;
py::bytes __cdecl AESEncrypt(char* text, py::bytes key) {
	if (key.attr("__len__").cast<int>() != 32){
		throw std::invalid_argument("Key is of wrong size");
	}
	try{
	unsigned char ivbuff[IV_SALT_LEN];
	unsigned char tag[AUTH_TAG_LEN];
	int msglen = strnlen((char*)text, MAX_CRYPTO_LEN);
	if (msglen == MAX_CRYPTO_LEN || msglen == MAX_CRYPTO_LEN) {
		throw std::invalid_argument("Error: this is not a null terminated string");
	}

	int rem = AUTH_TAG_LEN - (msglen % AUTH_TAG_LEN);
	unsigned char iv[IV_SALT_LEN];
	RAND_bytes(iv, IV_SALT_LEN);
	memcpy_s(&ivbuff, IV_SALT_LEN, iv, IV_SALT_LEN);
	auto out = unique_ptr<unsigned char[]>(new unsigned char[msglen + (long long)rem + (long long)1]);
	EVP_CIPHER_CTX* ctx;
	int len;
	int ciphertext_len;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SALT_LEN, NULL))
		handleErrors();
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char*)key.cast<char*>(), iv))
		handleErrors();
	if (1 != EVP_EncryptUpdate(ctx, out.get(), &len, (unsigned char*)text, msglen))
		handleErrors();
	ciphertext_len = len;
	if (1 != EVP_EncryptFinal_ex(ctx, out.get() + len, &len))
		handleErrors();
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LEN, &tag))
		handleErrors();
	ciphertext_len += len;
	OPENSSL_cleanse(text, msglen);
	EVP_CIPHER_CTX_free(ctx);
	int bufferLength = ciphertext_len + (long long)AUTH_TAG_LEN + (long long)IV_SALT_LEN;
	auto result = unique_ptr<unsigned char[]>(new unsigned char[bufferLength]);
	AddToStrBuilder((char*)result.get(), (char*)out.get(), 0, ciphertext_len);
	delete[] out.release();
	AddToStrBuilder((char*)result.get(), (char*)&tag, ciphertext_len, AUTH_TAG_LEN);
	AddToStrBuilder((char*)result.get(), (char*)&iv, ciphertext_len + AUTH_TAG_LEN, IV_SALT_LEN);
	py::bytes bresult = py::bytes((const char*)result.get(), bufferLength);
	return bresult;
	} catch(...) {
		throw std::invalid_argument("Unable to encrypt ciphertext");
	}
}

py::bytes __cdecl AESDecrypt(py::bytes ctext_b, py::bytes key){
	if (key.attr("__len__").cast<int>() != 32){
		throw std::invalid_argument("Key is of wrong size");
	}
	try {
	int input_len = ctext_b.attr("__len__").cast<int>();
	auto ctext = unique_ptr<unsigned char[]>(new unsigned char [input_len]);
	memcpy_s(ctext.get(), input_len, ctext_b.cast<char*>(), input_len);
	int msglen = IV_SALT_LEN - AUTH_TAG_LEN - IV_SALT_LEN;
	auto msg = unique_ptr<unsigned char[]>(new unsigned char[msglen]);
	memcpy_s(msg.get(), msglen, ctext.get(), msglen);
	unsigned char iv[IV_SALT_LEN];
	memcpy_s(iv, IV_SALT_LEN, ctext.get() + msglen + AUTH_TAG_LEN, IV_SALT_LEN);
	unsigned char tag[AUTH_TAG_LEN];
	memcpy_s(tag, AUTH_TAG_LEN, ctext.get() + msglen, AUTH_TAG_LEN);
	auto out = unique_ptr<unsigned char[]>(new unsigned char[msglen + (long long)1]);

	EVP_CIPHER_CTX* ctx;
	int len;
	int plaintext_len;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SALT_LEN, NULL))
		handleErrors();
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char*)key.cast<char*>(), iv))
		handleErrors();
	if (1 != EVP_DecryptUpdate(ctx, out.get(), &len, msg.get(), msglen))
		handleErrors();
	plaintext_len = len;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AUTH_TAG_LEN, tag))
		handleErrors();
	delete[] msg.release();
	int ret = EVP_DecryptFinal_ex(ctx, out.get() + len, &len);
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	if (!(ret >= 0)) {
		throw std::invalid_argument("Unable to decrypt ciphertext");
	}
	out[plaintext_len] = '\0';
	py::bytes r = py::bytes((char*)out.get());
	OPENSSL_cleanse((char*)out.get(),msglen + (long long)1);
	return r;
	} catch(...) {
		throw std::invalid_argument("Unable to decrypt ciphertext");
	}
}