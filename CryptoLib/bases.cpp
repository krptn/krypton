#include "CryptoLib.h"

#include <openssl/evp.h>
#include <pybind11/pybind11.h>

using namespace std;
namespace py = pybind11;

py::str encode64(char* data, int length) {
	int pl = (length+3-length%3)*4/3;
	char* output = new char[pl+1];
	pl = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), (const unsigned char*)data, length);
	OPENSSL_cleanse(data, length);
	py::str result = py::str((const char*)output, pl);
	OPENSSL_cleanse(output, pl+1);
	delete[] output;
	return result;
}

py::bytes decode64(char* input, int length) {
	const auto pl = (length/4)*3;
	int outLen;
	unsigned char* output = new unsigned char[pl+1];
	EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
	EVP_DecodeInit(ctx);
	if (EVP_DecodeUpdate(ctx, output, &outLen, (unsigned char*)input, length) == -1) {
		handleErrors();
	}
	int outputLen = outLen;
	if (EVP_DecodeFinal(ctx, output, &outLen) == -1) {
		handleErrors();
	}
	outputLen = outputLen + outLen;
	EVP_ENCODE_CTX_free(ctx);
	py::bytes result = py::bytes((const char*)output, outputLen);
	OPENSSL_cleanse(output, pl+1);
	OPENSSL_cleanse(input, length);
	delete[] output;
	return result;
}
