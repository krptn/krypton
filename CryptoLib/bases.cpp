#include "CryptoLib.h"

#include <sodium.h>
#include <pybind11/pybind11.h>

#include <memory>
#include <string>
#include <stdexcept>
#include <cstddef>

using namespace std;
namespace py = pybind11;

py::str encode64(std::string data)
{
	size_t len = sodium_base64_encoded_len(data.length(), sodium_base64_VARIANT_ORIGINAL);
	auto output = unique_ptr<char[]>(new char[len]);
	sodium_bin2base64(output.get(), len,
                        (const unsigned char*)data.c_str(), data.length(),
                        sodium_base64_VARIANT_ORIGINAL);
	py::str finalResult = py::str(output.get());
	sodium_memzero((void*)data.c_str(), data.length());
	sodium_memzero((void*)output.get(), len);
	return finalResult;
}

py::bytes decode64(std::string input)
{
	size_t len = input.length()/4 * 3;
	auto output = unique_ptr<unsigned char[]>(new unsigned char[len]);
	size_t trueLen = 0;
	const int status = sodium_base642bin(output.get(), len,
                      input.c_str(), input.length(),
                      NULL, &trueLen,
                      NULL, sodium_base64_VARIANT_ORIGINAL);
	py::bytes pythonBytes = py::bytes((char*)output.get(), trueLen);
	sodium_memzero((void*)input.c_str(), input.length());
	sodium_memzero((void*)output.get(), len);
	if (status != 0) throw std::invalid_argument("Unable to base64 decode data.");
	return pythonBytes;
}
