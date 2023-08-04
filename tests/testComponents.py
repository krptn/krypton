import unittest
import os
from krypton import base
from krypton.auth import factors

class CryptographicUnits(unittest.TestCase):
    def testAES(self):
        k = os.urandom(32)
        r = base.seal("Hello", k)
        fr = base.unSeal(r, k)
        self.assertEqual(fr, b"Hello")
    def testPasswordHash(self):
        kb = base.passwordHash("abcdrf", os.urandom(16), 3)
        self.assertIsInstance(kb, bytes)
        self.assertEqual(len(kb), 32)
    def testECCKeyGen(self):
        keys = base.createECCKey()
        self.assertEqual(len(keys), 2)
    def testEccEncrypt(self):
        keys = base.createECCKey()
        keys2 = base.createECCKey()
        text = b'Hello World'
        ctext = base.encryptEcc(keys[0], keys2[1], text)
        self.assertEqual(base.decryptEcc(keys2[0], keys[1], ctext), text)
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
