import unittest
import pysec
from pysec.basic import crypto
from pysec import globals
import os

TEST_PWD = "Example"
TEST_TEXT = "Example"
UPDATE_TEST_TEXT = "Example2"
class TestSecureStoreClass(unittest.TestCase):

    def WriteRead(self):
        test = crypto()
        a = test.secureCreate(TEST_TEXT,TEST_PWD)
        b = test.secureRead(a,TEST_PWD)
        test.secureDelete(a, TEST_PWD)
        self.assertEqual(TEST_TEXT,b)
    
    def WriteUpdateRead(self):
        test = crypto()
        a = test.secureCreate(TEST_TEXT, TEST_PWD)
        test.secureUpdate(a,UPDATE_TEST_TEXT,TEST_PWD)
        b = test.secureRead(a,TEST_PWD)
        self.assertEqual(UPDATE_TEST_TEXT,b)
    
    def WriteDelete(self):
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
        r = globals._restEncrypt(k, "Hello")
        fr = globals._restDecrypt(k, r)
        self.assertEqual(fr, "Hello")
    def testKDF(self):
        kb = globals._getKey("abcdrf")
        self.assertIsInstance(kb, bytes)
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
        self.assertEqual(text, t)
"""
class TestUserAuth(unittest.TestCase):
    pass
"""
if __name__ == "__main__":
    unittest.main()

