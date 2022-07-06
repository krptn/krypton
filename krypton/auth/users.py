"""
Provides User Models
"""

import datetime
import os
import pickle
from abc import ABCMeta, abstractmethod
from typing import ByteString, SupportsInt
from sqlalchemy import select, text, func
from tomlkit import date
from . import factors
from .. import DBschemas, basic, configs
from .. import base

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

class user(metaclass=ABCMeta):
    @abstractmethod
    def delete(self):
        """The method name says it all."""
    @abstractmethod
    def login(self, pwd:str, mfaToken:SupportsInt=None):
        """The method name says it all."""
    @abstractmethod
    def logout(self):
        """The method name says it all."""
    @abstractmethod
    def enableMFA(self):
        """The method name says it all."""
    @abstractmethod
    def disableMFA(self):
        """The method name says it all."""
    @abstractmethod
    def createOTP(self):
        """The method name says it all."""
    @abstractmethod
    def saveNewUser(self):
        """The method name says it all."""
    @abstractmethod
    def getData(self, __name: str) -> any:
        """The method name says it all."""
    @abstractmethod
    def setData(self, __name: str, __value: any) -> None:
        """The method name says it all."""
    @abstractmethod
    def decryptWithUserKey(self, data:ByteString, sender:str, salt:bytes) -> bytes:
        """The method name says it all."""
    @abstractmethod
    def encryptWithUserKey(self, data:ByteString, otherUsers:list[str]) -> bytes:
        """The method name says it all."""
    @abstractmethod
    def generateNewKeys(self, pwd):
        """The method name says it all."""
    @abstractmethod
    def resetPWD(self):
        """The method name says it all."""

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

    @userExistRequired
    def setData(self, __name: str, __value: any) -> None:
        """The method name says it all."""
        self.c.execute(
            text("INSERT INTO :id VALUES (:name, :value)"),
            {"id":self.id, "name":__name, "value":__value}
        )
        SQLDefaultUserDBpath.commit()
    @userExistRequired
    def getData(self, __name: str) -> any:
        """The method name says it all."""
        result = self.c.scalar(
            text("SELECT value FROM :id WHERE key=:name"),
            {"name":__name, "id":self.id}
        ).value # Don't forget to check backuped keys to decrypt data
        if result is None:
            raise AttributeError()
        return result
    @userExistRequired
    def delete(self):
        """The method name says it all."""
        pass

    @userExistRequired
    def login(self, pwd:str, otp:str, fido:str):
        """The method name says it all."""
        stmt = select(DBschemas.UserTable.pwdAuthToken).where(DBschemas.UserTable.id == self.id)
        try: authTag = self.c.scalar(stmt)[0]
        except: raise UserError("User must have a password set.")
        result = factors.password.auth(authTag, pwd)
        if result is False: raise UserError("User must have a password set.")
        key = b""
        token = DBschemas.SessionKeys(
            id = self.id,
            key = key,
            iss = datetime.datetime.now(),
            exp = datetime.datetime.now() + datetime.timedelta(minutes=configs.defaultSessionPeriod)
        )
        self.c.add(token)
        self.logedin = True
    
    @userExistRequired
    def logout(self):
        """The method name says it all."""

    @userExistRequired
    def resetPWD(self):
        """The method name says it all."""

    @userExistRequired
    def enableMFA(self):
        """The method name says it all."""

    @userExistRequired
    def disableMFA(self):
        """The method name says it all."""

    @userExistRequired
    def createOTP(self):
        """The method name says it all."""

    @userExistRequired
    def saveNewUser(self, **kwargs):
        """The method name says it all.
        It accepts following **kwargs: pwd:str, fido:str.
        """
        if self.saved:
            raise ValueError("This user is already saved.")
        
        salt = os.urandom(12)
        stmt = select(func.max(DBschemas.CryptoTable.id))
        self.id = self.c.scalar(stmt) + 1
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
    def decryptWithUserKey(self, data:ByteString, sender:str, salt:bytes) -> bytes:
        """The method name says it all."""
        # Will also need to check the backup keys if decryption fails
        key = base.getSharedKey(self.__privKey, sender, salt)

    @userExistRequired
    def encryptWithUserKey(self, data:ByteString, otherUsers:list[str]) -> list[tuple[str, bytes, bytes]]:
        """The method name says it all."""
        salts = [os.urandom(12) for name in otherUsers]
        AESKeys = [base.getSharedKey(self.__privKey, name, salts[i])
            for i, name in enumerate(otherUsers)]
        results = [base.restEncrypt(data, key) for key in AESKeys]
        for i in AESKeys: base.zeromem(i)
        return zip(otherUsers, results, salts)
    @userExistRequired
    def generateNewKeys(self, pwd):
        """The method name says it all."""
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
