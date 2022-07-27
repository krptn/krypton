#include "CryptoLib.h"
#include <pybind11/pybind11.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <string>
#include <cmath>

using namespace std;

namespace py = pybind11;

bool verifyTOTP(py::bytes secret, py::str value) {
    int codeLen = value.attr("__len__")().cast<int>();
    if (codeLen != 6) {
        return false;
    }
    char* key = pymbToBuffer(secret);
    int keylen = secret.attr("__len__")().cast<int>();
    char* code = pyStrToBuffer(value);
    int counter = floor(time(NULL)/30);
    unsigned char* md = new unsigned char[20];
    unsigned int len;
    unsigned char* result = HMAC(EVP_sha1(), key, keylen, (unsigned char*)&counter, sizeof(counter), md, &len);
    OPENSSL_cleanse(key, keylen);
    delete[] key;
    //int offset = md[19] & 0x3F;
    int offset = md[len-1] % 0xf;
    int bin_code = (md[offset] & 0x7f) << 24
		| (md[offset+1] & 0xff) << 16
		| (md[offset+2] & 0xff) << 8
		| (md[offset+3] & 0xff);
    bin_code = bin_code % (int)pow(10, 6);
    string strCode = to_string(bin_code);
    const char* cCode = strCode.c_str();
    int compR = compHash(&cCode, code, 6);
    delete[] code;
    delete[] md;
    if (compR == 0) {
        return true;
    }
    return false;
}