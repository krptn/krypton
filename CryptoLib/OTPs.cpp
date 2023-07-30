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

extern EVP_MD *OTP_HASH;

bool verifyTOTP(py::bytes secret, py::str value)
{
  int codeLen = value.attr("__len__")().cast<int>();
  int keylen = secret.attr("__len__")().cast<int>();
  if (codeLen != 6 || keylen != 20)
  {
    return false;
  }
  char *key = pymbToBuffer(secret);
  char *code = pyStrToBuffer(value);
  unsigned long long intCounter = time(NULL) / 30;
  unsigned char counter[sizeof(intCounter)];
  for (size_t i = 0; i < sizeof(intCounter); i++)
  {
    counter[i] = (char)((intCounter >> (7 - i) * 8) & 0xFF);
  }
  char md[20];
  unsigned int mdLen;
  HMAC(OTP_HASH, key, keylen, (const unsigned char *)&counter, sizeof(counter), (unsigned char *)&md, &mdLen);
  OPENSSL_cleanse(key, keylen);
  int offset = md[19] & 0x0f;
  int bin_code = (md[offset] & 0x7f) << 24 | (md[offset + 1] & 0xff) << 16 | (md[offset + 2] & 0xff) << 8 | (md[offset + 3] & 0xff);
  bin_code = bin_code % 1000000;
  char correctCode[7];
  snprintf((char *)&correctCode, 7, "%06d", bin_code);
  int compR = compHash(&correctCode, code, 6);
  delete[] key;
  delete[] code;
  if (compR == 0)
  {
    return true;
  }
  sleepOutOfGIL(5);
  return false;
}

py::str genOTP()
{
  unsigned char binCode[9];
  if (!(RAND_bytes((unsigned char *)&binCode, sizeof(binCode)) == 1))
  {
    handleErrors();
  }
  char finalCode[sizeof(binCode) * 4 / 3 + 1];
  EVP_EncodeBlock(reinterpret_cast<unsigned char *>(finalCode), (const unsigned char *)binCode, sizeof(binCode));
  py::str pyCode = py::str(finalCode, sizeof(binCode) * 4 / 3);
  OPENSSL_cleanse(&binCode, sizeof(binCode));
  OPENSSL_cleanse(&finalCode, sizeof(finalCode));
  return pyCode;
}

bool sleepOutOfGIL(int seconds)
{
  py::gil_scoped_release release;
  std::this_thread::sleep_for(std::chrono::seconds(seconds));
  py::gil_scoped_acquire acquire;
  return true;
}
