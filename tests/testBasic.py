import unittest
from krypton.basic import Crypto, KMS

TEST_PWD = "Example"
TEST_TEXT = "Example"
UPDATE_TEST_TEXT = "Example2"

class KeyManagement(unittest.TestCase):
    def test(self):
        id = "test Key"
        i = KMS()
        k = i.createNewKey(id, "Example")
        a = i.getKey(id, "Example")
        i.removeKey(id, "Example")
        self.assertEqual(len(a), 32)
        self.assertEqual(k, a)

class CryptoClass(unittest.TestCase):
    def testWriteReadDelete(self):
        test = Crypto()
        a = test.secureCreate(TEST_TEXT,TEST_PWD)
        b = test.secureRead(a,TEST_PWD)
        test.secureDelete(a, TEST_PWD)
        self.assertEqual(TEST_TEXT, b.decode())

    def testWriteUpdateRead(self):
        test = Crypto()
        a = test.secureCreate(TEST_TEXT, TEST_PWD)
        test.secureUpdate(a,UPDATE_TEST_TEXT,TEST_PWD)
        b = test.secureRead(a,TEST_PWD)
        test.secureDelete(a, TEST_PWD)
        self.assertEqual(UPDATE_TEST_TEXT, b.decode())

    def testWriteDelete(self):
        test = Crypto()
        a = test.secureCreate(TEST_TEXT, TEST_PWD)
        test.secureDelete(a, TEST_PWD)
        self.assertRaises(Exception, lambda: test.secureRead(a, TEST_PWD))

if __name__ == "__main__":
    unittest.main()
