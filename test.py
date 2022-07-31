from datetime import datetime
import hmac
import hashlib
import time

def int_to_bytestring(i: int, padding: int = 8) -> bytes:
        """
        Turns an integer to the OATH specified
        bytestring, which is fed to the HMAC
        along with the secret
        """
        result = bytearray()
        while i != 0:
                result.append(i & 0xFF)
                i >>= 8
        # It's necessary to convert the final result from bytearray to bytes
        # because the hmac functions in python 2.6 and 3.3 don't work with
        # bytearray
        return bytes(bytearray(reversed(result)).rjust(padding, b'\0'))

Testcode = '123456'
for_time = datetime.now()
timeCode = int(time.mktime(for_time.timetuple()) / 30)
secret = b'/9\xfa"=[\x0e\xfbu8\xef\xdb\x88\x00uz\xfc\xa0\xc7`'
print(timeCode)
print(int_to_bytestring(timeCode))
print(len(int_to_bytestring(timeCode)))
hasher = hmac.new(secret, int_to_bytestring(timeCode), hashlib.sha1)
hmac_hash = bytearray(hasher.digest())
offset = hmac_hash[-1] & 0xf
code = ((hmac_hash[offset] & 0x7f) << 24 |
        (hmac_hash[offset + 1] & 0xff) << 16 |
        (hmac_hash[offset + 2] & 0xff) << 8 |
        (hmac_hash[offset + 3] & 0xff))
str_code = str(code % 10 ** 6)

print("Offset: ", offset)
print("MD: ", hmac_hash)
print("Code:", str_code)

from krypton import base
input("")
print(base.verifyTOTP(secret, Testcode))
c=0
for i in int_to_bytestring(timeCode):
        c+=i
print(c)