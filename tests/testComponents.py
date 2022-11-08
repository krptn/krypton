import unittest
import os
from krypton import base
from krypton.auth import factors

class CryptographicUnits(unittest.TestCase):
    def testAES(self):
        k = os.urandom(32)
        r = base.restEncrypt("Hello", k)
        fr = base.restDecrypt(r, k)
        self.assertEqual(fr, b"Hello")
    def testPBKDF2(self):
        kb = base.PBKDF2("abcdrf", os.urandom(12), 100000)
        self.assertIsInstance(kb, bytes)
        self.assertEqual(len(kb), 32)
    def testECCKeyGen(self):
        keys = base.createECCKey()
        self.assertTrue(keys[0].startswith("-----BEGIN EC PRIVATE KEY-----\n") and keys[0].endswith("\n-----END EC PRIVATE KEY-----\n"))
        self.assertTrue(keys[1].startswith("-----BEGIN PUBLIC KEY-----\n") and keys[1].endswith("\n-----END PUBLIC KEY-----\n"))
    def testECDH(self):
        keys = base.createECCKey()
        keys2 = base.createECCKey()
        salt = os.urandom(12)
        key = base.ECDH(keys[0], keys2[1], salt, keylen=32)
        self.assertEqual(len(key), 32)
        self.assertEqual(key, base.ECDH(keys[0], keys2[1], salt, keylen=32))
    def testBase64(self):
        text = "fdgdfgfdgdfsr"
        b64 = base.base64encode(text)
        t = base.base64decode(b64)
        self.assertEqual(text, t.decode())

class AuthFactors(unittest.TestCase):
    def testPassword(self):
        TEST = "TEST"
        tag = factors.password.getAuth(TEST)
        result = factors.password.auth(tag, TEST)
        self.assertTrue(type(result) == bytes)
        self.assertTrue(len(result) == 32)

if __name__ == "__main__":
    unittest.main()
