import unittest
from pysec.basic import crypto, kms
from pysec import globals
import os

TEST_PWD = "Example"
TEST_TEXT = "Example"
UPDATE_TEST_TEXT = "Example2"

class TestKMS(unittest.TestCase):
    def test(self):
        id = os.urandom(32)
        i = kms()
        i.createNewKey(id, "Example")
        self.assertEqual(len(i.getKey(id, 'Example')), 32)
        i.removeKey(id, "Example")

class testCryptoClass(unittest.TestCase):
    def testWriteRead(self):
        test = crypto()
        a = test.secureCreate(TEST_TEXT,TEST_PWD)
        b = test.secureRead(a,TEST_PWD)
        test.secureDelete(a, TEST_PWD)
        self.assertEqual(TEST_TEXT,b)
    
    def testWriteUpdateRead(self):
        test = crypto()
        a = test.secureCreate(TEST_TEXT, TEST_PWD)
        test.secureUpdate(a,UPDATE_TEST_TEXT,TEST_PWD)
        b = test.secureRead(a,TEST_PWD)
        self.assertEqual(UPDATE_TEST_TEXT,b)
    
    def testWriteDelete(self):
        test = crypto()
        a = test.secureCreate(TEST_TEXT, TEST_PWD)
        test.secureDelete(a, TEST_PWD)
        working = False
        try:
            test.secureRead(a, TEST_PWD)
        except:
            working = True
        if working:
            self.assertFalse(False)
        else:
            self.assertFalse(True)

class TestCryptographicUnits(unittest.TestCase):
    def testAES(self):
        k = os.urandom(32)
        r = globals._restEncrypt("Hello", k)
        fr = globals._restDecrypt(r, k)
        self.assertEqual(fr, "Hello")
    def testPBKDF2(self):
        kb = globals.PBKDF2("abcdrf", os.urandom(12), 100000)
        self.assertIsInstance(kb, bytes)
        self.assertEqual(len(kb), 32)
    def testECCKeyGen(self):
        keys = globals.createECCKey()
        self.assertIs(len(keys[0]) > 2 and len(keys[1]) > 2)
    def testECDH(self):
        keys = globals.createECCKey()
        keys2 = globals.createECCKey()
        key = globals.getSharedKey(keys[1], keys2[0])
        self.assertEqual(len(key), 32)
    def testBase64(self):
        text = "fdgdfgfdgdfsr"
        b64 = globals.base64encode(text)
        t = globals.base64decode(b64)
        self.assertEqual(text, t.decode())
"""
class TestUserAuth(unittest.TestCase):
    pass
"""
if __name__ == "__main__":
    unittest.main()

