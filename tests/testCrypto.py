import unittest
from pysec.basic import crypto

class TestCryptoClass(unittest.TestCase):

    def test_creation(self):
        test = crypto()
        a = test.secureCreate("Example")
        b = test.sercureRead(a)
        self.assertEqual(a,b)

if __name__ == "__main__":
    unittest.main()

