#include "CryptoLib.h"
#include <pybind11/pybind11.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
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
    long int counter = floor(time(NULL)/30);
    int strCounterLen = floor(log(counter)/ log(10)) + 1;
    unsigned char* strCounter = new unsigned char[strCounterLen + 1];
    snprintf((char*)&strCounter, strCounterLen + 1,"%d", counter);
    unsigned char* md = new unsigned char[20];
    unsigned int len;
    HMAC(EVP_sha1(), key, keylen, strCounter, strCounterLen, md, &len);
    OPENSSL_cleanse(key, keylen);
    delete[] key;
    delete[] strCounter;
    int offset = md[19] & 0xf;
    //offset = offset % 0xf;
    int bin_code = (md[offset] & 0x7f) << 24
		| (md[offset+1] & 0xff) << 16
		| (md[offset+2] & 0xff) << 8
		| (md[offset+3] & 0xff);
    bin_code = bin_code % (int)pow(10, 6);
    char correctCode[7];
    snprintf((char*)&correctCode, 7,"%d", value);
    int compR = compHash(&code, code, 6);
    delete[] code;
    delete[] md;
    if (compR == 0) {
        return true;
    }
    return false;
}