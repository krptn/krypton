#include "CryptoLib.h"
#include <pybind11/pybind11.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <cmath>
#include <iostream>
#include <algorithm>

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
    int strCounterLen = 8;
    unsigned char* strCounter = new unsigned char[strCounterLen];
    //snprintf((char*)strCounter, strCounterLen + 1,"%d", counter);
    int c = 0;
    while (counter != 0) {
        strCounter[c++] = counter & 0xFF;
        counter >>= 8;
    }
    reverse(strCounter, strCounter+8);
    cout << "C: " << c;
    unsigned char* md = new unsigned char[20];
    unsigned int len;
    cout << "Key: " << key << "\n";
    cout << "Counter: " << strCounter << "\n";
    HMAC(EVP_sha1(), key, keylen, strCounter, strCounterLen, md, &len);
    OPENSSL_cleanse(key, keylen);
    cout << "MD: " << md << "\n";
    delete[] key;
    delete[] strCounter;
    int offset = md[19] & 0xf;
    cout << "Offset: " << offset << "\n";
    int bin_code = (md[offset] & 0x7f) << 24
		| (md[offset+1] & 0xff) << 16
		| (md[offset+2] & 0xff) << 8
		| (md[offset+3] & 0xff);
    bin_code = bin_code % (int)pow(10, 6);
    cout << "bin_code: " << bin_code << "\n";
    char correctCode[7];
    snprintf((char*)&correctCode, 7,"%06d", bin_code);
    int compR = compHash(&code, code, 6);
    delete[] code;
    delete[] md;
    if (compR == 0) {
        return true;
    }
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
    bin_code = bin_code % (int)pow(10, 6);
    char correctCode[7];
    snprintf((char*)&correctCode, 7,"%06d", bin_code);
    bin_code = 0;
    OPENSSL_cleanse(&secret, 20);
    py::str pyCode = py::str(correctCode, 6);
    OPENSSL_cleanse(&correctCode, 7);
    return pyCode;
}