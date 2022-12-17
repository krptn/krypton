import unittest
import uuid
from krypton.auth.users.bases import UserError
from krypton.auth.users.userModel import standardUser

class UserAuth(unittest.TestCase):
    def setUp(self) -> None:
        self.model = standardUser(None)
        self.userName = "Test"+str(uuid.uuid4())
        self.model.saveNewUser(str(uuid.uuid4()), "TEST")
        self.model.changeUserName(self.userName)
        return super().setUp()

    def tearDown(self) -> None:
        self.model.loggedin = True
        self.model.delete()
        return super().tearDown()

    def testLoginOut(self):
        self.model.logout()
        self.model.login(pwd="TEST")

    def testResetPWD(self):
        keys = self.model.enablePWDReset()
        self.model.setData("Before", "B")
        self.model.logout()
        self.model.resetPWD(keys[0], "newPWD")
        self.model.logout()
        self.model.login(pwd="newPWD")
        self.model.setData("test", "VALUE")
        a = self.model.getData("test")
        ctext = self.model.encryptWithUserKey("text")
        text = self.model.decryptWithUserKey(ctext)
        dataText = self.model.getData("Before")
        self.assertEqual(a, b"VALUE")
        self.assertEqual(text, b"text")
        self.assertEqual(b"B", dataText)

    def testKeyGenCrossUser(self):
        user2 = standardUser(None)
        user2Name = "user3"+str(uuid.uuid4())
        user2.saveNewUser(user2Name, "pwd")
        test = user2.encryptWithUserKey("data", [self.userName])
        user2.generateNewKeys("pwd")
        self.model.generateNewKeys("TEST")
        result = self.model.decryptWithUserKey(test[0][1], test[0][2], user2Name)
        user2.delete()
        self.assertEqual(result, b"data")

    def testSingleUserEncrypt(self):
        ctext = self.model.encryptWithUserKey("TEST")
        test = self.model.decryptWithUserKey(ctext)
        self.assertEqual(test, b"TEST")

    def testCrossUserEncrypt(self):
        user2 = standardUser(None)
        user2Name = "user3"+str(uuid.uuid4())
        user2.saveNewUser(user2Name, "pwd")
        test = user2.encryptWithUserKey("data", [self.userName])
        result = self.model.decryptWithUserKey(test[0][1], test[0][2], user2Name)
        user2.delete()
        self.assertEqual(result, b"data")

    def testShare(self):
        user2 = standardUser(None)
        user2.saveNewUser("user4"+str(uuid.uuid4()), "pwd")
        testName = "test"+str(uuid.uuid4())
        user2.shareSet(testName, "TesT", [self.userName])
        value = self.model.shareGet(testName)
        user2.delete()
        self.assertEqual(value, b"TesT")

    def testDB(self):
        self.model.setData("test", b"TEST_VALUE")
        result = self.model.getData("test")
        self.model.deleteData("test")
        self.assertEqual(result, b"TEST_VALUE")

    def testSessions(self):
        self.model.logout()
        key = self.model.login(pwd="TEST")
        newMod = standardUser(userName=self.userName)
        newMod.restoreSession(key)
        self.assertTrue(newMod.loggedin)

    def testLogout(self):
        self.model.logout()
        key = self.model.login(pwd="TEST")
        self.model.logout()
        newMod = standardUser(userName=self.userName)
        try:
            newMod.restoreSession(key)
        except UserError:
            self.assertTrue(True)
        else:
            self.assertTrue(False)

if __name__ == "__main__":
    unittest.main()
