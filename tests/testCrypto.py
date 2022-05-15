import unittest
from pysec.basic import crypto

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
    pass
class TestUserAuth(unittest.TestCase):
    pass

if __name__ == "__main__":
    unittest.main()

