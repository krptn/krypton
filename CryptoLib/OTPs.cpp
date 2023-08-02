#include "CryptoLib.h"

#include <pybind11/pybind11.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <sodium.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

using namespace std;

namespace py = pybind11;

#define OTP_BUFFER_RAND_LEN 12

bool verifyTOTP(std::string secret, std::string value)
{
  int codeLen = value.length();
  int keylen = secret.length();
  if (codeLen != 6 || keylen != 20)
  {
    return false;
  }
  const char *key = secret.c_str();
  const char *code = value.c_str();
  unsigned long long intCounter = time(NULL) / 30;
  unsigned char counter[sizeof(intCounter)];
  for (size_t i = 0; i < sizeof(intCounter); i++)
  {
    counter[i] = (char)((intCounter >> (7 - i) * 8) & 0xFF);
  }
  char md[20];
  unsigned int mdLen;
  HMAC(EVP_sha1(), key, keylen, (const unsigned char *)&counter, sizeof(counter), (unsigned char *)&md, &mdLen);
  OPENSSL_cleanse((void *)key, keylen);
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
  unsigned char otp[OTP_BUFFER_RAND_LEN];
  randombytes_buf(&otp, OTP_BUFFER_RAND_LEN);
  size_t len = sodium_base64_encoded_len(OTP_BUFFER_RAND_LEN, sodium_base64_VARIANT_ORIGINAL);
  auto output = unique_ptr<char[]>(new char[len]);
  sodium_bin2base64(output.get(), len,
                    (unsigned char *)&otp, OTP_BUFFER_RAND_LEN,
                    sodium_base64_VARIANT_ORIGINAL);
  py::str finalResult = py::str(output.get());
  sodium_memzero((void *)&otp, OTP_BUFFER_RAND_LEN);
  return finalResult;
}

bool sleepOutOfGIL(int seconds)
{
  py::gil_scoped_release release;
  std::this_thread::sleep_for(std::chrono::seconds(seconds));
  py::gil_scoped_acquire acquire;
  return true;
}
