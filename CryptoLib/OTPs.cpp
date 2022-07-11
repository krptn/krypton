#include "CryptoLib.h"
#include <pybind11/pybind11.h>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>


namespace py = pybind11;

bool verifyTOTP(py::bytes secret, py::bytes value) {
    char* key = pymbToBuffer(secret);
    int keylen = secret.attr("__len__")().cast<int>();
    char* code = pymbToBuffer(value);
    int codeLen = value.attr("__len__")().cast<int>();
    long long int unix_timestamp = std::chrono::seconds (std::time (NULL)).count();
    int counter = floor(unix_timestamp/30);
    unsigned char* md = new unsigned char[EVP_MAX_MD_SIZE];
    unsigned int len;
    unsigned char* result = HMAC(EVP_sha256(), key, keylen, (unsigned char*)counter, sizeof(counter), md, &len);
    OPENSSL_cleanse(key, keylen);
    if (codeLen != len) {
        return false;
    }
    int compR = compHash(md, code, len);
    if (compR == 0){
        return true;
    }
    return false;
}