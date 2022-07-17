import unittest
from krypton.auth import users

class userAuth(unittest.TestCase):
    def setUp(self) -> None:
        self.model = users.standardUser(None)
        self.model.saveNewUser("Test", "TEST")
        return super().setUp()
    def tearDown(self) -> None:
        self.model.loggedin = True
        self.model.delete()
        return super().tearDown()
    def testLoginOut(self):
        self.model.logout()
        self.model.login(pwd="TEST")
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
    def testDB(self):
        self.model.setData("test", b"TEST_VALUE")
        result = self.model.getData("test")
        self.model.deleteData("test")
        self.assertEqual(result, b"TEST_VALUE")

if __name__ == "__main__":
    unittest.main()
