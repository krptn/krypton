import unittest
from pysec.Basic import crypto

class TestKMS(unittest.TestCase):

    def test_creation(self):
        test = crypto()
        a = test.secureCipher("Example")
        b = test.secureDecipher(a)
        self.assertEqual(a,b)

if __name__ == "__main__":
    unittest.main()

