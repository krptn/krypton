// Cross-PlatformCryptoLib.cpp : Defines the entry point for the application.
// -fdeclspec -cfguard" for ninja buildArgs
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
using namespace std;
namespace py = pybind11;

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
  auto output = reinterpret_cast<char *>(calloc(pl+1, 1));
  const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), input, length);
  length = pl;
  return output;
}

unsigned char *decode64(const char *input, int length) {
  const auto pl = 3*length/4;
  auto output = reinterpret_cast<unsigned char *>(calloc(pl+1, 1));
  const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);
  length = pl;
  return output;
}

void handleErrors(int* err) {
	//Add to log here
	*err = *err + 1;
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


char* __cdecl AESEncrypt(char* text, char* key) {
	if (strlen((char*)text) > 549755813632) {
		throw std::invalid_argument("Data is too long or is not null terminated");
	}
	try{
	unsigned char ivbuff[12];
	unsigned char tag[16];
	int errcnt = 0;
	int msglen = strnlen((char*)text, 549755813632);
	if (msglen == 549755813632 || msglen == 549755813631) {
		throw std::invalid_argument("Error: this is not a null terminated string");
	}

	int rem = 16 - (msglen % 16);
	unsigned char iv[12];
	RAND_bytes(iv, 12);
	memcpy_s(&ivbuff, 12, iv, 12);
	auto out = unique_ptr<unsigned char[]>(new unsigned char[msglen + (long long)rem + (long long)1]);
	EVP_CIPHER_CTX* ctx;
	int len;
	int ciphertext_len;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors(&errcnt);
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors(&errcnt);
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
		handleErrors(&errcnt);
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char*)key, iv))
		handleErrors(&errcnt);
	if (1 != EVP_EncryptUpdate(ctx, out.get(), &len, (unsigned char*)text, msglen))
		handleErrors(&errcnt);
	ciphertext_len = len;
	if (1 != EVP_EncryptFinal_ex(ctx, out.get() + len, &len))
		handleErrors(&errcnt);
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, &tag))
		handleErrors(&errcnt);
	ciphertext_len += len;
	OPENSSL_cleanse(key, 32);
	OPENSSL_cleanse(text, msglen);
	EVP_CIPHER_CTX_free(ctx);
	if (errcnt != 0) {
		throw std::invalid_argument("Unable to encrypt");
	}
	auto result = unique_ptr<unsigned char[]>(new unsigned char[ciphertext_len + (long long)16 + (long long)12 + (long long)1 + (long long)12]);
	AddToStrBuilder((char*)result.get(), (char*)out.get(), 0, ciphertext_len);
	delete[] out.release();
	AddToStrBuilder((char*)result.get(), (char*)&tag, ciphertext_len, 16);
	AddToStrBuilder((char*)result.get(), (char*)&iv, ciphertext_len + 16, 12);
	unsigned char len_num[12]{};
	string num = to_string(msglen);
	int ler = num.length();
	const char* num_len = num.c_str();
	AddToStrBuilder((char*)result.get(), (char*)num_len, ciphertext_len + 12 + 16 + (12 - ler), ler);
	memset(result.get() + ciphertext_len + 12 + 16, '0', ((long long)12 - ler));
	result[ciphertext_len + (long long)16 + (long long)12 + (long long)12] = '\0';
	int fl = ciphertext_len + (long long)16 + (long long)12 + (long long)1 + (long long)12;
	auto fresult = base64(result.get(),fl);
	return (char*)fresult;
	} catch(...) {
		throw std::invalid_argument("Unable to encrypt ciphertext");
	}
}

py::bytes __cdecl AESDecrypt(char* ctext_b, char* key){
	try {
	char len_str[13];
	int input_len = strlen(ctext_b);
	auto dctext = decode64(ctext_b,input_len);
	auto ctext = unique_ptr<unsigned char[]>(new unsigned char [input_len]);
	memcpy_s(ctext.get(), input_len, dctext, input_len);
	memcpy_s(len_str, 12, ctext.get() + input_len - 12, 12);
	free(dctext);
	if (strnlen((char*)ctext.get(), 549755813632) == 549755813632 || strnlen((char*)ctext.get(), 549755813632) == 549755813631) {
		throw std::invalid_argument("Error: this is not a null terminated string");
	}
	len_str[12] = '\0';
	string str_lena = string(len_str);
	int flen = stoi(str_lena);
	int errcnt = 0;
	int leny = b.size();
	int msglen = leny - 12 - 16 - 12;
	auto msg = unique_ptr<unsigned char[]>(new unsigned char[msglen]);
	memcpy_s(msg.get(), msglen, ctext.get(), msglen);
	unsigned char iv[12];
	memcpy_s(iv, 12, ctext.get() + msglen + 16, 12);
	unsigned char tag[16];
	memcpy_s(tag, 16, ctext.get() + msglen, 16);
	auto out = unique_ptr<unsigned char[]>(new unsigned char[msglen + (long long)1]);

	EVP_CIPHER_CTX* ctx;
	int len;
	int plaintext_len;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors(&errcnt);
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors(&errcnt);
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
		handleErrors(&errcnt);
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char*)key, iv))
		handleErrors(&errcnt);
	if (1 != EVP_DecryptUpdate(ctx, out.get(), &len, msg.get(), msglen))
		handleErrors(&errcnt);
	plaintext_len = len;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		handleErrors(&errcnt);
	delete[] msg.release();
	int ret = EVP_DecryptFinal_ex(ctx, out.get() + len, &len);
	plaintext_len += len;

	OPENSSL_cleanse(key, 32);
	EVP_CIPHER_CTX_free(ctx);
	if ((!(ret >= 0)) || (errcnt > 0)) {
		throw std::invalid_argument("Unable to decrypt ciphertext");
	}
	if (flen > msglen + (long long)1) {
		throw std::invalid_argument("Unable to decrpt ciphertext: a bufferoverflow on the heap has occured.");
	}
	out[flen] = '\0';
	py::bytes r = py::bytes((char*)out.get());
	OPENSSL_cleanse((char*)out.get(),msglen + (long long)1);
	return r;
	} catch(...) {
		throw std::invalid_argument("Unable to decrypt ciphertext");
	}
}

char* __cdecl hashForStorage(char* text) {
	char* key = new char[32];
	char salt[12];
	int len = strlen(text);
	RAND_bytes((unsigned char*)&salt, 12);
	int a;
	a = PKCS5_PBKDF2_HMAC(text, len, (unsigned char*)&salt, 12, 1000000,EVP_sha512(), 32, (unsigned char*)key);
	OPENSSL_cleanse(text, len);
	if (a != 1) {
		throw std::invalid_argument("Unable to hash data.");
	}
	auto new_b = base64((const unsigned char*)key,32);
	return new_b;
}

py::bytes __cdecl getKeyFromPass(char* pwd) {
	char* key = new char[32];
	char salt[12];
	int len = strlen(pwd);
	RAND_bytes((unsigned char*)&salt, 12);
	int a;
	a = PKCS5_PBKDF2_HMAC(pwd, len, (unsigned char*)&salt, 12, 100000, EVP_sha512(), 32, (unsigned char*)key);
	OPENSSL_cleanse(pwd, len);
	if (a != 1) {
		throw std::invalid_argument("Unable to hash data.");
	}
	return py::bytes(key,32);
}

py::bytes __cdecl Auth(char* pwd, char* storedHash) {	
	int errcnt = 0;
	int len = strlen(pwd);
	int hashLen = strlen(storedHash);
	auto decoded = unique_ptr<char[]>(new char[hashLen+(long long)1]);
	auto b = decode64(storedHash,hashLen);
	if (hashLen != 44) {
		throw std::invalid_argument("The stored hash is of incorrect length.");
	}
	memcpy_s(decoded.get(), strlen(storedHash) + (long long)1 -(long long)12, b, hashLen-(long long)12);
	free(b);
	auto salt = unique_ptr<char[]>(new char[12]);
	memcpy_s(salt.get(), 12, decoded.get() + ((hashLen+(long long)1) - (long long)12),12);
	auto key = unique_ptr<char[]>(new char[32]);
	auto keya = unique_ptr<char[]>(new char[32]);
	if(!PKCS5_PBKDF2_HMAC(pwd, len, (unsigned char*)&salt, 12, 1000000, EVP_sha512(), 32, (unsigned char*)keya.get()))
		handleErrors(&errcnt);
	int x;
	x = PKCS5_PBKDF2_HMAC(pwd, len, (unsigned char*)&salt, 12, 100000, EVP_sha512(), 32, (unsigned char*)key.get());
	OPENSSL_cleanse(pwd, len);
	if (x != 1) {
		handleErrors(&errcnt);
	}
	if (compHash(decoded.get(), keya.get(), 32)==0) {
		if (errcnt != 0) {
			OPENSSL_cleanse(key.get(), 32);
			OPENSSL_cleanse(pwd, len);
			throw std::invalid_argument("Authentication failed.");
		}
		else {
			auto result = py::bytes(key.get(), 32);
			OPENSSL_cleanse(key.get(), 32);
			OPENSSL_cleanse(pwd, len);
			return result;
		}
	}
	else {
		OPENSSL_cleanse(key.get(), 32);
		OPENSSL_cleanse(pwd, len);
		throw std::invalid_argument("Authentication failed.");
	}
	return pwd;
};

char* __cdecl PBKDF2(char* text, char* salt) {
	char* key = new char[32];
	int len = strlen(text);
	int a;
	a = PKCS5_PBKDF2_HMAC(text, len, (const unsigned char*) salt, 12, 1000000, EVP_sha512(), 32, (unsigned char*)key);
	OPENSSL_cleanse(text, len);
	if (a != 1) {
		throw std::invalid_argument("Unable to hash data.");
	}
	auto result = base64((const unsigned char*)key,32);
	delete[] key;
	return result;
}

int init()
{
	OSSL_PROVIDER *fips;
	fips = OSSL_PROVIDER_load(NULL, "fips");
	if (fips == NULL) {
		printf("Failed to load FIPS provider\n");
		exit(EXIT_FAILURE);
	}
}

PYBIND11_MODULE(CryptoLib, m) {
	m.doc() = "Cryptographical component of PySec. Only for use inside the PySec module.";
	m.def("AESDecrypt", &AESDecrypt, "A function which decrypts the data. Args: text, key.", py::arg("ctext"), py::arg("key"));
	m.def("AESEncrypt", &AESEncrypt, "A function which encrypts the data. Args: text, key.", py::arg("text"), py::arg("key"));
	m.def("hashForStorage", &hashForStorage, "Securely hashes the text", py::arg("text"));
	m.def("Auth", &Auth, "Authneticates users using values supplied. Returns user's crypto key is authentication successfull, returns 'Error' otherwise.", py::arg("pwd"), py::arg("stored_HASH")='\0');
	m.def("getKeyFromPass", &getKeyFromPass, "Uses PBKDF2 to get the crypto key from the password.", py::arg("pwd"));
	m.def("compHash", &compHash, "Compares hashes", py::arg("a"), py::arg("a"), py::arg("len")); 
	m.def("PBKDF2", &PBKDF2, "Performs PBKDF2 on text and salt", py::arg("text"), py::arg("salt"));
	m.def("init",&init,"Initialises cryptographic components. ");
}
