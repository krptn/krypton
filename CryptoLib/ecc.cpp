#include "CryptoLib.h"

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <pybind11/pybind11.h>

using namespace std;
namespace py = pybind11;

int ECC_DEFAULT_CURVE = NID_secp521r1;
const char* KEY_ENCODE_FORMAT = "PEM";

size_t getPubKey(EVP_PKEY *pkey, char* out) {
	OSSL_ENCODER_CTX *ctx;
	unsigned char* data = NULL;
	size_t datalen;
	ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_PUBLIC_KEY, KEY_ENCODE_FORMAT, NULL, NULL);
	if (ctx == NULL)
		handleErrors();
	if (OSSL_ENCODER_CTX_get_num_encoders(ctx) == 0)
		handleErrors();
	if (!OSSL_ENCODER_to_data(ctx, &data, &datalen))
		handleErrors();
	if (out != NULL) {
		memcpy(out, data, datalen);
	}
	OPENSSL_free(data);
	OSSL_ENCODER_CTX_free(ctx);
	return datalen;
}

size_t getPrivKey(EVP_PKEY *pkey, char* out) {
	OSSL_ENCODER_CTX *ctx;
	unsigned char* data = NULL;
	size_t datalen;
	ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR, KEY_ENCODE_FORMAT, NULL, NULL);
	if (ctx == NULL)
		handleErrors();
	if (OSSL_ENCODER_CTX_get_num_encoders(ctx) == 0)
		handleErrors();
	if (!OSSL_ENCODER_to_data(ctx, &data, &datalen))
		handleErrors();
	if (out != NULL) {
		memcpy(out, data, datalen);
	}
	OPENSSL_cleanse(data, datalen);
	OPENSSL_free(data);
	OSSL_ENCODER_CTX_free(ctx);
	return datalen;
}

int setPubKey(EVP_PKEY **pkey, char* key, int len) {
	OSSL_DECODER_CTX *ctx;
	ctx = OSSL_DECODER_CTX_new_for_pkey(pkey, KEY_ENCODE_FORMAT, NULL, "EC", EVP_PKEY_PUBLIC_KEY, NULL, NULL);
	if (ctx == NULL)
		handleErrors();
	if (OSSL_DECODER_CTX_get_num_decoders(ctx) == 0)
		handleErrors();
	if (!OSSL_DECODER_from_data(ctx, (const unsigned char**)&key, (size_t*)&len))
		handleErrors();
	OSSL_DECODER_CTX_free(ctx);
	return 1;
}

int setPrivKey(EVP_PKEY **pkey, char* key, int len) {
	OSSL_DECODER_CTX *ctx;
	ctx = OSSL_DECODER_CTX_new_for_pkey(pkey, KEY_ENCODE_FORMAT, NULL, "EC", EVP_PKEY_KEYPAIR, NULL, NULL);
	if (ctx == NULL)
		handleErrors();
	if (OSSL_DECODER_CTX_get_num_decoders(ctx) == 0)
		handleErrors();
	if (!OSSL_DECODER_from_data(ctx, (const unsigned char**)&key, (size_t*)&len))
		handleErrors();
	OSSL_DECODER_CTX_free(ctx);
	return 1;
}

py::tuple createECCKey() {
	char* pubResult;
	char* privResult;
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
	pubResult = new char[len];
	getPubKey(pkey, pubResult);
	py::str r = py::str((char*)pubResult, len);
	OPENSSL_cleanse(pubResult, len);
	delete[] pubResult;
	len = getPrivKey(pkey, NULL);
	privResult = new char[len];
	getPrivKey(pkey, privResult);
	py::str pr = py::str(privResult, len);
	OPENSSL_cleanse(privResult, len);
	delete[] privResult;
	EVP_PKEY_free(pkey);
	py::tuple finalTuple = py::make_tuple(pr, r);
	return finalTuple;
}

py::bytes ECDH(py::str privKey, py::str pubKey, py::bytes salt, int keylen) {
	EVP_PKEY* pkey = NULL;
	EVP_PKEY* peerkey = NULL;
	EVP_PKEY_CTX *ctx;
	size_t secretLen;
	int saltLen = salt.attr("__len__")().cast<int>();
	char* C_salt = pymbToBuffer(salt);
	char* privk = pyStrToBuffer(privKey);
	int privkLen = privKey.attr("__len__")().cast<int>();
	setPrivKey(&pkey, privk, privkLen);
	char* pubk = pyStrToBuffer(pubKey);
	int pubkLen = privKey.attr("__len__")().cast<int>();
	setPubKey(&peerkey, pubk, pubkLen);
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if(!ctx) handleErrors();
	if(1 != EVP_PKEY_derive_init(ctx)) handleErrors();
	if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) handleErrors();
	if(1 != EVP_PKEY_derive(ctx, NULL, &secretLen)) handleErrors();
	unsigned char* secret = new unsigned char[secretLen];
	if(1 != (EVP_PKEY_derive(ctx, secret, &secretLen))) handleErrors();
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peerkey);
	EVP_PKEY_free(pkey);
	py::bytes key = pyHKDF((char*)secret, (int)secretLen, C_salt, saltLen, keylen);
	OPENSSL_cleanse(secret, secretLen);
	OPENSSL_cleanse(privk, privkLen);
	delete[] secret;
	delete[] privk;
	delete[] pubk;
	delete[] C_salt;
	return key;
}
