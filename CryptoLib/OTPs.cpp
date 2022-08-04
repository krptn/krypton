#include "CryptoLib.h"
#include <pybind11/pybind11.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <cmath>
#include <iostream>
#include <algorithm>
#include <thread>
#include <chrono>

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
    time_t unixTime = floor(time(NULL));
    unixTime = mktime(gmtime(&unixTime));
    int intCounter = unixTime/30;
    char counter[8];
    int c = 0;
    while (counter != 0) {
        counter[c++] = intCounter & 0xFF;
        intCounter >>= 8;
    }

    unsigned char md[20];
    HMAC(EVP_sha1(), key, keylen, (const unsigned char*)&counter, 8, (unsigned char*)&md, NULL);
    OPENSSL_cleanse(key, keylen);
    int offset = md[19] & 0x0f;
    int bin_code = (md[offset] & 0x7f) << 24
		| (md[offset+1] & 0xff) << 16
		| (md[offset+2] & 0xff) << 8
		| (md[offset+3] & 0xff);
    bin_code = bin_code % (int)pow(10, 6);
    char correctCode[7];
    snprintf((char*)&correctCode, 7,"%06d", bin_code);
    int compR = compHash(&code, code, 6);
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