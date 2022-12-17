#include "CryptoLib.h"

#include <openssl/evp.h>
#include <pybind11/pybind11.h>

using namespace std;
namespace py = pybind11;

char* encode64(char* data, int length) {
	int inputLen = length+3-length%3;
	char* input = new char[inputLen];
	memcpy(input, data, length);
	int pl = (inputLen)*4/3;
	input[inputLen-1] = length;
	char* output = new char[pl+1];
	EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), (const unsigned char*)input, inputLen);
	delete[] input;
	return output;
}

py::bytes decode64(char* input, int length) {
	int pl = (length/4)*3;
	unsigned char* output = new unsigned char[pl+1];
	if (EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length) == -1)
		handleErrors();
	pl = (int)output[pl-1];
	py::bytes result = py::bytes((const char*)output, pl);
	delete[] output;
	return result;
}
