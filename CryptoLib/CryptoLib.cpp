// Cross-PlatformCryptoLib.cpp : Defines the entry point for the application.
// -fdeclspec -cfguard" for ninja buildArgs
#include "CryptoLib.h"
#include <pybind11/pybind11.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
using namespace std;
namespace py = pybind11;

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

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

std::string decode64(const std::string& val) {
	using namespace boost::archive::iterators;
	using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
	return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(val)), It(std::end(val))), [](char c) {
		return c == '\0';
		});
}

std::string encode64(const std::string& val) {
	using namespace boost::archive::iterators;
	using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
	auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
	return tmp.append((3 - val.size() % 3) % 3, '=');
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
	if (msglen == 549755813632 || msglen == 549755813631) {
		throw std::invalid_argument("Error: this is not a null terminated string");
	}

	int rem = 16 - (msglen % 16);
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
	//unsigned char* result = new unsigned char[ciphertext_len+(long long)16+ (long long)12+(long long)1];
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

	/*
	OSSL_PROVIDER_unload(base);
	OSSL_PROVIDER_unload(fips);
	*/
	result[ciphertext_len + (long long)16 + (long long)12 + (long long)12] = '\0';
	string d = string();
	d.resize(ciphertext_len + (long long)16 + (long long)12 + (long long)12);
	memcpy_s((void*)d.c_str(), ciphertext_len + (long long)16 + (long long)12 + (long long)12,result.get(), ciphertext_len + (long long)16 + (long long)12 + (long long)12);
	string r = encode64(d);
	char* f = new char[r.size()+(long long)1];
	memcpy_s(f, r.size(), r.c_str(), r.size());
	int to_change = r.length();
	f[to_change] = '\0';
	return (char*)f;
	} catch(...) {
		throw std::invalid_argument("Unable to encrypt ciphertext");
	}
}

py::bytes __cdecl AESDecrypt(char* ctext_b, char* key){
	try {
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
	auto a = string((const char*)ctext_b);
	auto b = decode64(a);
	auto ctext = unique_ptr<unsigned char[]>(new unsigned char[b.size()+(long long)1]);
	ctext[b.size()]='\0';
	memcpy_s(ctext.get(), b.size(), b.c_str(), b.size());
	memcpy_s(len_str, 12, ctext.get() + b.size() - 12, 12);
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
	/*
	OSSL_PROVIDER_unload(base);
	OSSL_PROVIDER_unload(fips);
	*/
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
/*
int __cdecl Init() {
	//EVP_set_default_properties(NULL, "fips=yes");
	EVP_add_cipher(EVP_aes_256_gcm());
	if (FIPS_mode_set(2) == 0) {
		return 0;
	}
	return 1;
};
*/
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
	auto x = string(key, 32);
	auto b = encode64(x);
	char* new_b = new char[b.size() + (long long)1];
	memcpy_s(new_b, b.size(), b.c_str(), b.size());
	new_b[b.size()] = '\0';
	return new_b;
}

py::bytes __cdecl Auth(char* pwd, char* storedHash) {	
	int errcnt = 0;
	int len = strlen(pwd);
	auto decoded = unique_ptr<char[]>(new char[strlen(storedHash)+(long long)1]);
	string a = string(storedHash);
	string b = decode64(a);
	if (b.length() != 44) {
		throw std::invalid_argument("The stored hash is of incorrect length.");
	}
	memcpy_s(decoded.get(), strlen(storedHash) + (long long)1 -(long long)12, b.c_str(), b.length()-(long long)12);
	auto salt = unique_ptr<char[]>(new char[12]);
	memcpy_s(salt.get(), 12, decoded.get() + ((b.length()+(long long)1) - (long long)12),12);
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

PYBIND11_MODULE(CryptoLib, m) {
	m.doc() = "Cryptographical component of PySec. Only for use inside the PySec module.";
	m.def("AESDecrypt", &AESDecrypt, "A function which decrypts the data. Args: text, key.", py::arg("ctext"), py::arg("key"));
	m.def("AESEncrypt", &AESEncrypt, "A function which encrypts the data. Args: text, key.", py::arg("text"), py::arg("key"));
	m.def("hashForStorage", &hashForStorage, "Securely hashes the text", py::arg("text"));
	m.def("Auth", &Auth, "Authneticates users using values supplied. Returns user's crypto key is authentication successfull, returns 'Error' otherwise.", py::arg("pwd"), py::arg("stored_HASH")='\0');
}
