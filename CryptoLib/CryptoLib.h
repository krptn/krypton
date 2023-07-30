// CryptoLib.h : Include file for standard system include files,
// or project specific include files.

#pragma once
#define OPENSSL_NO_DEPRECATED

#include <pybind11/pybind11.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

namespace py = pybind11;

#define ECC_DEFAULT_CURVE NID_secp521r1
#define KEY_ENCODE_FORMAT "PEM"
#define AES_KEY_LEN 32
#define IV_SALT_LEN 12
#define AUTH_TAG_LEN 16

// General
py::str encode64(char *data, int length);
py::bytes decode64(char *input, int length);
void handleErrors();
char *pymbToBuffer(py::bytes a);
char *pyStrToBuffer(py::str a);

// AES
py::bytes AESEncrypt(char *textc, py::bytes key, int msglenc);
py::bytes AESDecrypt(py::bytes ctext_b, py::bytes key);

// Hashes
int compHash(const void *a, const void *b, const size_t size);
py::bytes pyPBKDF2(char *text, int len, char *salt, int iter, int saltLen, int keylen = 32);
py::bytes pyHKDF(char *secret, int len, char *salt, int saltLen, int keylen);

// ECC
py::tuple createECCKey();
py::bytes ECDH(py::str privKey, py::str pubKey, py::bytes salt, int keylen);
size_t getPubKey(EVP_PKEY *pkey, char *out);
size_t getPrivKey(EVP_PKEY *pkey, char *out);
int setPubKey(EVP_PKEY **pkey, char *key, int len);
int setPrivKey(EVP_PKEY **pkey, char *key, int len);

// OTPs
bool verifyTOTP(py::bytes secret, py::str value);
py::str genOTP();
bool sleepOutOfGIL(int seconds = 5);
