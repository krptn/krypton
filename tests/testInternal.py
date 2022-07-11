import unittest
from krypton.auth import users

class userAuth(unittest.TestCase):
    def testCreateNewUser(self):
        model = users.standardUser(None)
        model.saveNewUser("Test", "TEST")
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
    def testDelete(self):
        pass
    def testDB(self):
        pass

if __name__ == "__main__":
    unittest.main()
