import hmac
import hashlib

secret = b'/9\xfa"=[\x0e\xfbu8\xef\xdb\x88\x00uz\xfc\xa0\xc7`'

hasher = hmac.new(secret, b"55300405", hashlib.sha1)
hmac_hash = bytearray(hasher.digest())
offset = hmac_hash[-1] & 0xf
code = ((hmac_hash[offset] & 0x7f) << 24 |
        (hmac_hash[offset + 1] & 0xff) << 16 |
        (hmac_hash[offset + 2] & 0xff) << 8 |
        (hmac_hash[offset + 3] & 0xff))
str_code = str(code % 10 ** 6)

print(offset)
print(str_code)
print(hmac_hash)