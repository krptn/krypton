#include "CryptoLib.h"
#include <pybind11/pybind11.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/applink.c>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/encoder.h>

using namespace std;
namespace py = pybind11;

int MAX_CRYPTO_LEN = 549755813632;
int PBKDF2_STORAGE_ITERATIONS = 1000000;
int PBKDF2_KEY_ITERATIONS = 100000;
const int AES_KEY_LEN = 32;
const int IV_SALT_LEN = 12;
const int AUTH_TAG_LEN = 16;
const auto PBKDF2_HASH_ALGO = EVP_sha512;
int ECC_DEFAULT_CURVE = NID_X9_62_prime256v1;
OSSL_PROVIDER *fips;

bool fipsInit()
{
	fips = OSSL_PROVIDER_load(NULL, "fips");
	if (fips == NULL) {
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to load fips provider.");
		return false; 
	}
	return true;
}

int compHash(const void* a, const void* b, const size_t size)
{
	const unsigned char* _a = (const unsigned char*)a;
	const unsigned char* _b = (const unsigned char*)b;
	unsigned char result = 0;
	size_t i;

	for (i = 0; i < size; i++) {
		result |= _a[i] ^ _b[i];
	}

	return result; /* returns 0 if equal, nonzero otherwise */
}

char *base64(const unsigned char *input, int length) {
  const auto pl = 4*((length+2)/3);
  char* output = new char[pl+1];
  const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), input, length);
  output[length] = '\0';
  return output;
}

unsigned char *decode64(const char *input, int length) {
  const auto pl = 3*length/4;
  unsigned char* output = new unsigned char[pl+1];
  const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);
  output[length] = '\0';
  return output;
}

py::bytes py_decode64(const char *input, int length) {
  const auto pl = 3*length/4;
  unsigned char* output = new unsigned char[pl+1];
  const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);
  py::bytes result = py::bytes((const char*)output, length);
  return result;
}

void handleErrors() {
	throw invalid_argument("Unable to perform cryptographic operation");
}

int __cdecl AddToStrBuilder(char* buffer, char* content, int len, int Optionalstrlen = 0) {
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

char* __cdecl hashForStorage(char* text) {
	char* key = new char[AES_KEY_LEN];
	char salt[IV_SALT_LEN];
	int len = strlen(text);
	RAND_bytes((unsigned char*)&salt, IV_SALT_LEN);
	int a;
	a = PKCS5_PBKDF2_HMAC(text, len, (unsigned char*)&salt, IV_SALT_LEN, PBKDF2_STORAGE_ITERATIONS,PBKDF2_HASH_ALGO(), AES_KEY_LEN, (unsigned char*)key);
	OPENSSL_cleanse(text, len);
	if (a != 1) {
		throw std::invalid_argument("Unable to hash data.");
	}
	auto new_b = base64((const unsigned char*)key,AES_KEY_LEN);
	return new_b;
}

py::bytes __cdecl getKeyFromPass(char* pwd) {
	char* key = new char[AES_KEY_LEN];
	char salt[IV_SALT_LEN];
	int len = strlen(pwd);
	RAND_bytes((unsigned char*)&salt, IV_SALT_LEN);
	int a;
	a = PKCS5_PBKDF2_HMAC(pwd, len, (unsigned char*)&salt, IV_SALT_LEN, PBKDF2_KEY_ITERATIONS, PBKDF2_HASH_ALGO(), AES_KEY_LEN, (unsigned char*)key);
	OPENSSL_cleanse(pwd, len);
	if (a != 1) {
		throw std::invalid_argument("Unable to hash data.");
	}
	return py::bytes(key,AES_KEY_LEN);
}

py::bytes __cdecl Auth(char* pwd, char* storedHash) {	
	int len = strlen(pwd);
	int hashLen = strlen(storedHash);
	auto decoded = unique_ptr<char[]>(new char[hashLen+(long long)1]);
	auto b = decode64(storedHash,hashLen);
	if (hashLen != 44) {
		throw std::invalid_argument("The stored hash is of incorrect length.");
	}
	memcpy_s(decoded.get(), strlen(storedHash) + (long long)1 -(long long)IV_SALT_LEN, b, hashLen-(long long)IV_SALT_LEN);
	delete[] b;
	auto salt = unique_ptr<char[]>(new char[IV_SALT_LEN]);
	memcpy_s(salt.get(), IV_SALT_LEN, decoded.get() + ((hashLen+(long long)1) - (long long)IV_SALT_LEN),IV_SALT_LEN);
	auto key = unique_ptr<char[]>(new char[AES_KEY_LEN]);
	auto keya = unique_ptr<char[]>(new char[AES_KEY_LEN]);
	if(!PKCS5_PBKDF2_HMAC(pwd, len, (unsigned char*)&salt, IV_SALT_LEN, PBKDF2_STORAGE_ITERATIONS, PBKDF2_HASH_ALGO(), AES_KEY_LEN, (unsigned char*)keya.get()))
		handleErrors();
	int x;
	x = PKCS5_PBKDF2_HMAC(pwd, len, (unsigned char*)&salt, IV_SALT_LEN, PBKDF2_KEY_ITERATIONS, PBKDF2_HASH_ALGO(), AES_KEY_LEN, (unsigned char*)key.get());
	OPENSSL_cleanse(pwd, len);
	if (x != 1) {
		handleErrors();
	}
	if (compHash(decoded.get(), keya.get(), AES_KEY_LEN)==0) {
		auto result = py::bytes(key.get(), AES_KEY_LEN);
		OPENSSL_cleanse(key.get(), AES_KEY_LEN);
		OPENSSL_cleanse(pwd, len);
		return result;
	}
	else {
		OPENSSL_cleanse(key.get(), AES_KEY_LEN);
		OPENSSL_cleanse(pwd, len);
		throw std::invalid_argument("Authentication failed.");
	}
	return pwd;
};

char* __cdecl PBKDF2(char* text, char* salt) {
	char* key = new char[AES_KEY_LEN];
	int len = strlen(text);
	int a;
	a = PKCS5_PBKDF2_HMAC(text, len, (const unsigned char*) salt, IV_SALT_LEN, PBKDF2_KEY_ITERATIONS, PBKDF2_HASH_ALGO(), AES_KEY_LEN, (unsigned char*)key);
	OPENSSL_cleanse(text, len);
	if (a != 1) {
		throw std::invalid_argument("Unable to hash data.");
	}
	auto result = base64((const unsigned char*)key,AES_KEY_LEN);
	delete[] key;
	return result;
};

int getPubKey(EVP_PKEY *pkey, char* out){
	OSSL_ENCODER_CTX *ctx;
	unsigned char* data = NULL;
	size_t datalen;
	ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_PUBLIC_KEY, "PEM", "SubjectPublicKeyInfo", NULL);
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
	ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR, "PEM", "PrivateKeyInfo", NULL);
	if (1 != OSSL_ENCODER_CTX_set_cipher(ctx, NULL, NULL)) handleErrors();
	if (!OSSL_ENCODER_to_data(ctx, &data, &datalen)) handleErrors();
	memcpy_s(out, datalen, data, datalen);
	OPENSSL_free(data);
	return datalen;
}

// https://www.openssl.org/docs/man3.0/man3/OSSL_DECODER_CTX_new_for_pkey.html
int setPubKey(EVP_PKEY *pkey, char* key, int len){
	OSSL_ENCODER_CTX *ctx;
}

int setPrivKey(EVP_PKEY *pkey, char* key, int len){

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
	int len = getPubKey(pkey, NULL);
	privResult = new unsigned char[len];
	py::bytes pr = py::bytes((char*)privResult, len);
	OPENSSL_cleanse(privResult, len);
	delete[] privResult;
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	tuple<py::bytes, py::bytes> finalTuple(pr, r);
	return finalTuple;
};

py::bytes __cdecl getSharedKey(py::bytes privKey, py::bytes pubKey){
	int secret_len = 32;
	EVP_PKEY* pkey;
	char* privk = privKey.cast<char*>();
	setPrivKey(pkey, privk, privKey.attr("__len__").cast<int>());
	EVP_PKEY* peerkey;
	char* pubk = pubKey.cast<char*>();
	setPubKey(peerkey, pubk, privKey.attr("__len__").cast<int>());
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
	py::bytes key = getKeyFromPass((char*)pwd);
	delete[] pwd;
	return key;
};

PYBIND11_MODULE(__CryptoLib, m) {
	m.doc() = "Cryptographical component of PySec. Only for use inside the PySec module.";
	m.def("AESDecrypt", &AESDecrypt, "A function which decrypts the data. Args: text, key.", py::arg("ctext"), py::arg("key"));
	m.def("AESEncrypt", &AESEncrypt, "A function which encrypts the data. Args: text, key.", py::arg("text"), py::arg("key"));
	m.def("hashForStorage", &hashForStorage, "Securely hashes the text", py::arg("text"));
	m.def("Auth", &Auth, 
		"Authneticates users using values supplied. Returns user's crypto key is authentication successfull, returns 'Error' otherwise.",
		 py::arg("pwd"), py::arg("stored_HASH")='\0'
	);
	m.def("getKeyFromPass", &getKeyFromPass, "Uses PBKDF2 to get the crypto key from the password.", py::arg("pwd"));
	m.def("compHash", &compHash, "Compares hashes", py::arg("a"), py::arg("a"), py::arg("len")); 
	m.def("PBKDF2", &PBKDF2, "Performs PBKDF2 on text and salt", py::arg("text"), py::arg("salt"));
	m.def("fipsInit",&fipsInit,"Initialises openssl FIPS module.");
	m.def("createECCKey", &createECCKey, "Create a new ECC private key");
	m.def("getECCSharedKey", &getSharedKey, "Uses ECDH to get a shared 256-bit key", py::arg("privKey"), py::arg("pubKey"));
	m.def("base64encode", &base64, "Base 64 encode data with length.", py::arg("data"), py::arg("length"));
	m.def("base64decode", &py_decode64, "Base 64 decode data with length.", py::arg("data"), py::arg("length"));
}
