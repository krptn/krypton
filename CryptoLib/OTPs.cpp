#include "CryptoLib.h"
#include <pybind11/pybind11.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <iostream>
#include <thread>
#include <chrono>

using namespace std;

namespace py = pybind11;

bool verifyTOTP(py::bytes secret, py::str value) {
    int codeLen = value.attr("__len__")().cast<int>();
    int keylen = secret.attr("__len__")().cast<int>();
    if (codeLen != 6 || keylen != 20) {
        return false;
    }
    char* key = pymbToBuffer(secret);
    char* code = pyStrToBuffer(value);
    unsigned long long intCounter = time(NULL)/30;
    unsigned long long endianness = 0xdeadbeef;
    if ((*(const uint8_t *)&endianness) == 0xef) {
      intCounter = ((intCounter & 0x00000000ffffffff) << 32) | ((intCounter & 0xffffffff00000000) >> 32);
      intCounter = ((intCounter & 0x0000ffff0000ffff) << 16) | ((intCounter & 0xffff0000ffff0000) >> 16);
      intCounter = ((intCounter & 0x00ff00ff00ff00ff) <<  8) | ((intCounter & 0xff00ff00ff00ff00) >>  8);
    };
    char md[20];
    unsigned int mdLen;
    HMAC(EVP_sha1(), key, keylen, (const unsigned char*)&intCounter, sizeof(intCounter), (unsigned char*)&md, &mdLen);
    OPENSSL_cleanse(key, keylen);
    int offset = md[19] & 0x0f;
    int bin_code = (md[offset] & 0x7f) << 24
		| (md[offset+1] & 0xff) << 16
		| (md[offset+2] & 0xff) << 8
		| (md[offset+3] & 0xff);
    bin_code = bin_code % 1000000;
    char correctCode[7];
    snprintf((char*)&correctCode, 7,"%06d", bin_code);
    int compR = compHash(&correctCode, code, 6);
    delete[] key;
    delete[] code;
    if (compR == 0) {
        return true;
    }
    std::this_thread::sleep_for(std::chrono::seconds(5));
    return false;
}

py::str genOTP() {
    unsigned char secret[20];
    RAND_bytes((unsigned char*)&secret, 20);
    int offset = secret[19] & 0xf;
    int bin_code = (secret[offset] & 0x7f) << 24
		| (secret[offset+1] & 0xff) << 16
		| (secret[offset+2] & 0xff) << 8
		| (secret[offset+3] & 0xff);
    bin_code = bin_code % (int)pow(10, 8);
    char correctCode[9];
    snprintf((char*)&correctCode, 9,"%08d", bin_code);
    bin_code = 0;
    OPENSSL_cleanse(&secret, 20);
    py::str pyCode = py::str(correctCode, 8);
    OPENSSL_cleanse(&correctCode, 9);
    return pyCode;
}