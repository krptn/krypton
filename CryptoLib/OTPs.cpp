#include "CryptoLib.h"

#include <pybind11/pybind11.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <sodium.h>

using namespace std;

namespace py = pybind11;

#define OTP_BUFFER_RAND_LEN 12

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
