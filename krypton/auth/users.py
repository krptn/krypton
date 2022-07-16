"""
Provides User Models
"""

import datetime
import os
import pickle
from typing import ByteString, SupportsInt
from sqlalchemy import delete, select, func
from functools import wraps
from . import factors, _utils
from .bases import user
from .. import DBschemas, configs, Globalsalt
from .. import base

ITER = 500000
LEN = 32
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
    @wraps(func)
    def inner1(self, *args, **kwargs):
        if self.saved:
            return func(self, *args, **kwargs)
        else:
            raise UserError("This user has not yet been saved.")
    return inner1

class standardUser(user):
    """Please pass None to __init__ to create a new user, after that call saveNewUser with required args."""
    _userName:str = ""
    __key:bytes = None
    salt:bytes
    saved = True
    loggedin = False
    backupKeys:list[str]
    backupAESKeys:list[bytes]
    def __init__(self, userID:int) -> None:
        super().__init__()
        self.c = configs.SQLDefaultUserDBpath
        if userID == None:
            self.saved = False
            return
        self.id = userID
        stmt = select(DBschemas.UserTable.name).where(DBschemas.UserTable.id == userID).limit(1)
        try: self._userName = self.c.scalar(stmt)[0]
        except:
            self.saved = False
        self.__privKey = self.getData("userPrivateKey")
        self.pubKey = self.getData("userPublicKey")

    @userExistRequired
    def setData(self, name: str, value: any) -> None:
        """The method name says it all."""
        try: self.deleteData(name)
        except: pass
        entry = DBschemas.UserData(
            Uid = self.id,
            name = base.PBKDF2(name, self.salt), ## Problem: How to raise iteration count
            value = base.restEncrypt(value, self.__key)
        )
        self.c.add(entry)
        self.c.commit()
    @userExistRequired
    def getData(self, name: str) -> any:
        """The method name says it all."""
        stmt = select(DBschemas.UserData.value).where(DBschemas.UserData.name == base.PBKDF2(name, self.salt)
            and DBschemas.UserData.Uid == self.id)
        result = self.c.scalar(stmt)
        # Don't forget to check backuped keys to decrypt data
        if result is None:
            raise AttributeError()
        text = base.restDecrypt(result, self.__key)
        return text
    
    @userExistRequired
    def deleteData(self, name:str) -> None:
        stmt = delete(DBschemas.UserData).where(DBschemas.UserData.name == base.PBKDF2(name, self.salt)  
            and DBschemas.UserData.Uid == self.id)
        self.c.execute(stmt)

    @userExistRequired
    def delete(self):
        """The method name says it all."""
        _utils.cleanUpSessions(self.id)
        stmt = select(DBschemas.UserTable).where(DBschemas.UserTable.id == self.id)
        values = self.c.scalar(stmt)
        self.c.delete(values)
        stmt = select(DBschemas.PubKeyTable).where(DBschemas.PubKeyTable.name == self.id)
        values = self.c.scalar(stmt)
        self.c.delete(values)
        self.c.execute(delete(DBschemas.UserData).where(DBschemas.UserData.Uid == self.id))
        self.c.flush()
        self.c.commit()
        return None

    @userExistRequired
    def login(self, pwd:str, otp:str, fido:str):
        """The method name says it all."""
        stmt = select(DBschemas.UserTable.pwdAuthToken).where(DBschemas.UserTable.id == self.id).limit(1)
        try: authTag = self.c.scalar(stmt)[0]
        except: raise UserError("User must have a password set.")
        self.__key = factors.password.auth(authTag, pwd)
        if self.__key is False: raise UserError("User must have a password set.")
        key = os.urandom(32)
        token = DBschemas.SessionKeys(
            id = self.id,
            key = base.restEncrypt(self.__key, key),
            iss = datetime.datetime.now(),
            exp = datetime.datetime.now() + datetime.timedelta(minutes=configs.defaultSessionPeriod)
        )
        self.c.add(token)
        self.c.commit()
        self.loggedin = True
        return key
    
    @userExistRequired
    def logout(self):
        """The method name says it all."""
    
    @userExistRequired
    def restoreSession(self, key):
        """The method name says it all."""
        _utils.cleanUpSessions()
        stmt = select(DBschemas.SessionKeys).where(DBschemas.SessionKeys.Uid == self.id).limit(1)
        row:DBschemas.SessionKeys = self.c.scalars(stmt)[0]
        """if row.exp < datetime.datetime.now(): # Because we just cleaned up sessions it is uneeded
            raise UserError("Session has expired")"""
        self.__key = base.restDecrypt(row.key, key)
    
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
    def saveNewUser(self, name:str, pwd:str, fido:str=None):
        """The method name says it all.
        It accepts following args: pwd:str, fido:str, name:str.
        """
        if self.saved:
            raise ValueError("This user is already saved.")
        
        self.salt = os.urandom(12)
        stmt = select(func.max(DBschemas.UserTable.id))
        self.id = self.c.scalar(stmt) + 1
        keys = base.createECCKey()
        self.pubKey = keys[0]
        self.__privKey = keys[1]
        key = DBschemas.PubKeyTable(
            name = self.id,
            key = self.pubKey
        )
        self.c.add(key)
        tag = factors.password.getAuth(pwd)
        userEntry = DBschemas.UserTable(
            id = self.id,
            name = base.PBKDF2(name, Globalsalt, ITER, LEN),
            pwdAuthToken = tag,
            salt = self.salt
        )
        self.c.add(userEntry)
        self.c.flush()
        self.__key = factors.password.auth(tag, pwd)
        self.saved = True
        self.setData("userPrivateKey", self.__privKey)
        self.setData("userPublicKey", self.pubKey)
        self.setData("backupKeys", pickle.dumps([]))
        self.setData("backupAESKeys", pickle.dumps([]))
        self.c.flush()
        self.c.commit()
    
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
        self.__key = os.urandom(32)
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
        self.c.flush()
        self.setData("userPrivateKey", self.__privKey)
        self.setData("userPublicKey", self.pubKey)
        self.setData("accountKeysCreation", datetime.now().year)
