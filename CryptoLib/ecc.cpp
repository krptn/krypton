#include "CryptoLib.h"

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <pybind11/pybind11.h>
using namespace std;

namespace py = pybind11;

int ECC_DEFAULT_CURVE = NID_X9_62_prime256v1;
const char* KEY_ENCODE_FORMAT = "PEM";
const char* CIPHER_TYPE = "ECC";
const int IV_SALT_LEN = 12;

int getPubKey(EVP_PKEY *pkey, char* out){
	OSSL_ENCODER_CTX *ctx;
	unsigned char* data = NULL;
	size_t datalen;
	ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_PUBLIC_KEY, KEY_ENCODE_FORMAT, "SubjectPublicKeyInfo", NULL);
	if (1 != OSSL_ENCODER_CTX_set_cipher(ctx, NULL, NULL)) handleErrors();
	if (!OSSL_ENCODER_to_data(ctx, &data, &datalen)) handleErrors();
	memcpy_s(out, datalen, data, datalen);
	OPENSSL_free(data);
	return datalen;
}

// https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_fromdata.html
// https://www.openssl.org/docs/man3.0/man3/OSSL_ENCODER_to_bio.html
// https://www.openssl.org/docs/man3.0/man3/OSSL_ENCODER_CTX_new_for_pkey.html#Output-types
int getPrivKey(EVP_PKEY *pkey, char* out){
	OSSL_ENCODER_CTX *ctx;
	unsigned char* data = NULL;
	size_t datalen;
	ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR, KEY_ENCODE_FORMAT, "PrivateKeyInfo", NULL);
	if (1 != OSSL_ENCODER_CTX_set_cipher(ctx, NULL, NULL)) handleErrors();
	if (!OSSL_ENCODER_to_data(ctx, &data, &datalen)) handleErrors();
	memcpy_s(out, datalen, data, datalen);
	OPENSSL_free(data);
	return datalen;
}

// https://www.openssl.org/docs/man3.0/man3/OSSL_DECODER_CTX_new_for_pkey.html
int setPubKey(EVP_PKEY *pkey, char* key, int len){
	OSSL_DECODER_CTX *ctx;
	ctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, KEY_ENCODE_FORMAT, "SubjectPublicKeyInfo", NULL, EVP_PKEY_PUBLIC_KEY, NULL, NULL);
	if (!OSSL_DECODER_from_data(ctx, (const unsigned char**)&key, (size_t*)&len)) handleErrors();
	return 1;
}

int setPrivKey(EVP_PKEY *pkey, char* key, int len){
	OSSL_DECODER_CTX *ctx;
	ctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, KEY_ENCODE_FORMAT, "PrivateKeyInfo", NULL, EVP_PKEY_KEYPAIR, NULL, NULL);
	if (!OSSL_DECODER_from_data(ctx, (const unsigned char**)&key, (size_t*)&len)) handleErrors();
	return 1;
}
std::tuple<py::bytes, py::bytes> __cdecl createECCKey() {
	unsigned char* pubResult;
	unsigned char* privResult;
	EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL)
        handleErrors();
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        handleErrors();
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, ECC_DEFAULT_CURVE) <= 0)
        handleErrors();
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        handleErrors();
	EVP_PKEY_CTX_free(ctx);
	int len = getPubKey(pkey, NULL);
	pubResult = new unsigned char[len];
	py::bytes r = py::bytes((char*)pubResult, len);
	OPENSSL_cleanse(pubResult, len);
	delete[] pubResult;
	len = getPubKey(pkey, NULL);
	privResult = new unsigned char[len];
	py::bytes pr = py::bytes((char*)privResult, len);
	OPENSSL_cleanse(privResult, len);
	delete[] privResult;
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	tuple<py::bytes, py::bytes> finalTuple(pr, r);
	return finalTuple;
};

py::bytes __cdecl getSharedKey(py::bytes privKey, py::bytes pubKey, py::bytes salt, int iter){
	int secret_len = 32;
	EVP_PKEY* pkey;
	char privk = privKey.cast<char>();
	setPrivKey(pkey, &privk, privKey.attr("__len__")().cast<int>());
	EVP_PKEY* peerkey;
	char pubk = pubKey.cast<char>();
	setPubKey(peerkey, &pubk, privKey.attr("__len__")().cast<int>());
	EVP_PKEY_CTX *ctx;
	if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) handleErrors();
	if(1 != EVP_PKEY_derive_init(ctx)) handleErrors();
	if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) handleErrors();
	if(1 != EVP_PKEY_derive(ctx, NULL, (size_t*)&secret_len)) handleErrors();
	auto secret = unique_ptr<unsigned char[]>(new unsigned char[IV_SALT_LEN]);
	if(1 != (EVP_PKEY_derive(ctx, secret.get(), (size_t*)&secret_len))) handleErrors();
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peerkey);
	EVP_PKEY_free(pkey);
	char* pwd = base64(secret.get(), secret_len);
	char C_salt = salt.cast<char>();
	py::bytes key = PBKDF2((char*)pwd, &C_salt, iter);
	delete[] pwd;
	return key;
};
