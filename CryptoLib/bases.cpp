#include "CryptoLib.h"

#include <openssl/evp.h>
#include <pybind11/pybind11.h>

using namespace std;
namespace py = pybind11;

char* encode64(char* data, int length) {
	int pl = (length+length%3)*4/3;
	char* output = new char[pl+1];
	EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), (const unsigned char*)data, length);
	return output;
}

py::bytes decode64(char* input, int length) {
	const auto pl = (length/4)*3;
	unsigned char* output = new unsigned char[pl+1];
	if (EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length) == -1)
		handleErrors();
	py::bytes result = py::bytes((const char*)output, pl).attr("rstrip")(py::bytes("\x00", 1));
	return result;
}
