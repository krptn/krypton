"""
Provides User Authentication
"""

from datetime import datetime
import os
import pickle
from abc import ABCMeta, abstractmethod
from typing import ByteString
from sqlalchemy import select, text
from . import DBschemas, basic, configs
from . import base

SQLDefaultUserDBpath = configs.SQLDefaultUserDBpath

class UserError(Exception):
    """
    Exception to be raised when an error occures in a user model.
    """
    def __init__(self, *args: object) -> None:
        self.message = args[0]
        super().__init__()
    def __str__(self) -> str:
        return self.message

def userExistRequired(func):
    def inner1(*args, **kwargs):
        if args[0].saved:
            func(*args, **kwargs)
        else:
            raise UserError("This user has not yet been saved.")

def logon(userName):
    stmt = select(DBschemas.UserTable.id).where(DBschemas.UserTable.name == userName).limit(1)


class user(metaclass=ABCMeta):
    @abstractmethod
    def delete(self):
        pass
    @abstractmethod
    def login(self, pwd:str, mfaToken:int|None=None):
        pass
    @abstractmethod
    def logout(self):
        pass
    @abstractmethod
    def enableMFA(self):
        pass
    @abstractmethod
    def disableMFA(self):
        pass
    @abstractmethod
    def createOTP(self):
        pass
    @abstractmethod
    def saveNewUser(self):
        pass
    @abstractmethod
    def getData(self, __name: str) -> any:
        pass
    @abstractmethod
    def setData(self, __name: str, __value: any) -> None:
        pass
    @abstractmethod
    def decryptWithUserKey(self, data:ByteString, sender:str, salt:bytes) -> bytes:
        pass
    @abstractmethod
    def encryptWithUserKey(self, data:ByteString, otherUsers:list[str]) -> bytes:
        pass
    @abstractmethod
    def generateNewKeys(self, pwd):
        pass
    @abstractmethod
    def resetPWD(self):
        pass

class standardUser(user):
    _userName:str = ""
    __key:bytes
    saved = True
    logedin = False
    keys:basic.KMS
    def __init__(self, userName:str) -> None:
        super().__init__()
        self.__privKey = self.getData("userPrivateKey")
        self.pubKey = self.getData("userPublicKey")
        self.c = SQLDefaultUserDBpath
        self._userName = userName
        stmt = select(DBschemas.UserTable.id).where(DBschemas.UserTable.name == userName).limit(1)
        try: self.id = self.c.scalar(stmt)[0]
        except:
            self.saved = False
            stmt = select(DBschemas.UserTable.id).where(DBschemas.UserTable.name == userName).limit(1)
            self.id = self.c.scalar(stmt)[0]

    @userExistRequired
    def setData(self, __name: str, __value: any) -> None:
        self.c.execute(
            text("INSERT INTO :id VALUES (:name, :value)"),
            {"id":self.id, "name":__name, "value":__value}
        )
        SQLDefaultUserDBpath.commit()
    @userExistRequired
    def getData(self, __name: str) -> any:
        result = self.c.scalar(
            text("SELECT value FROM :id WHERE key=:name"),
            {"name":__name, "id":self.id}
        ).value # Don't forget to check backuped keys to decrypt data
        if result is None:
            raise AttributeError()
        return result
    @userExistRequired
    def delete(self):
        pass
    @userExistRequired
    def login(self, pwd:str, mfaToken:int|None=None):
        self.keys = basic.KMS(SQLDefaultUserDBpath)
        try:
            self.__key = self.keys.getKey(self.id, pwd)
        except basic.KeyManagementError:
            self.generateNewKeys(pwd)
        self.logedin = True
    @userExistRequired
    def logout(self):
        pass
    @userExistRequired
    def resetPWD(self):
        pass
    @userExistRequired
    def enableMFA(self):
        pass
    @userExistRequired
    def disableMFA(self):
        pass
    @userExistRequired
    def createOTP(self):
        pass
    @userExistRequired
    def saveNewUser(self):
        if self.saved:
            raise ValueError("This user is already saved.")
        salt = os.urandom(12)
        self.id = base.base64encode(base.PBKDF2(self._userName, salt, configs.defaultIterations))
        keys = base.createECCKey()
        self.pubKey = keys[0]
        self.__privKey = keys[1]
        self.c.execute(f"CREATE TABLE {id} (key text, value blob)".format(id=self.id))
        key = DBschemas.PubKeyTable(
            name = self.id,
            key = self.pubKey
        )
        self.c.add(key)
        self.setData("userPrivateKey", self.__privKey)
        self.setData("userPublicKey", self.pubKey)
        self.setData("userSalt", salt)
        self.setData("backupKeys", pickle.dumps([]))
        self.setData("backupAESKeys", pickle.dumps([]))
    @userExistRequired
    def decryptWithUserKey(self, data:ByteString, sender:str, salt:bytes) -> bytes: # Will also need to check the backup keys if decryption fails
        key = base.getSharedKey(self.__privKey, sender, salt)

    @userExistRequired
    def encryptWithUserKey(self, data:ByteString, otherUsers:list[str]) -> list[tuple[str, bytes, bytes]]:
        salts = [os.urandom(12) for name in otherUsers]
        AESKeys = [base.getSharedKey(self.__privKey, name, salts[i], configs.defaultIterations)
            for i, name in enumerate(otherUsers)]
        results = [base._restEncrypt(data, key) for key in AESKeys]
        for i in AESKeys: base.zeromem(i)
        return zip(otherUsers, results, salts)
    @userExistRequired
    def generateNewKeys(self, pwd): # Both symetric and Public/Private
        keys = base.createECCKey()
        backups = self.getData("backupKeys")
        backupList:list[bytes] = pickle.loads(backups)
        backupList.append(self.__privKey)
        self.setData("backupKeys", pickle.dumps(backupList))
        for x in backups: base.zeromem(x)
        base.zeromem(backups)
        backups = self.getData("backupAESKeys")
        backupList:list[bytes] = pickle.loads(backups)
        backupList.append(self.__key)
        self.setData("backupAESKeys", pickle.dumps(backupList))
        for x in backups: base.zeromem(x)
        base.zeromem(backups)

        self.keys.removeKey(self.id, pwd)
        self.__key = self.keys.createNewKey(self.id, pwd)
        self.__privKey = keys[0]
        self.pubKey = keys[1]
        stmt = select(DBschemas.PubKeyTable).where(DBschemas.PubKeyTable.name == self.id)
        stmt = self.c.scalar(stmt)
        self.c.delete(stmt)
        key = DBschemas.PubKeyTable(
            name = self.id,
            key = self.pubKey
        )
        self.c.add(key)
        self.setData("userPrivateKey", self.__privKey)
        self.setData("userPublicKey", self.pubKey)
        self.setData("accountKeysCreation", datetime.now().year)
