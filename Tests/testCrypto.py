import unittest

from PySec.Basic import kms
import os
try:
    os.remove("PySec.key")
except:
    pass

class TestSum(unittest.TestCase):

    def test_creation(self):
        k = kms()
        k.configTable("example")
        k.getTableKey("example")

        self.assertIsInstance(k.getTableKey("example"), bytes, "Should be bytes")

if __name__ == "__main__":
    unittest.main()

