#include "CryptoLib.h"
#include <openssl/evp.h>
#include <pybind11/pybind11.h>
using namespace std;
namespace py = pybind11;

char* base64(char* data, int length) {
	int pl;
	if (length%3 == 0) {
		pl = length*4;
	} else {
		pl = 4*((length+(3-(length%3)))/3);
	}
	char* output = new char[pl+1];
	const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), (const unsigned char*)data, length);
	output[pl] = '\0';
	return output;
}

unsigned char *decode64(char* input, int length) {
	const auto pl = (length/4)*3;
	unsigned char* output = new unsigned char[pl+1];
	const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);
	output[pl] = '\0';
	return output;
}

py::bytes py_decode64(const char* input, int length) {
	const auto pl = (length/4)*3;
	unsigned char* output = new unsigned char[pl+1];
	const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);
	output[pl] = '\0';
	py::bytes result = py::bytes((const char*)output, pl).attr("rstrip")(py::bytes("\x00", 1));
	return result;
}
