import unittest
from krypton.auth import users

class userAuth(unittest.TestCase):
    def setUp(self) -> None:
        self.model = users.standardUser(None)
        self.model.saveNewUser("Test", "TEST")
        return super().setUp()
    def tearDown(self) -> None:
        self.model.delete()
        return super().tearDown()
    def testLoginOut(self):
        pass
    def testResetPWD(self):
        pass
    def testEncrypt(self):
        pass
    def testDecrypt(self):
        pass
    def testMFA(self):
        pass
    def testOTP(self):
        pass
    def testLoginOut(self):
        pass
    def testDB(self):
        self.model.setData("test", b"TEST_VALUE")
        result = self.model.getData("test")
        self.model.deleteData("test")
        self.assertEqual(result, b"TEST_VALUE")

if __name__ == "__main__":
    unittest.main()
