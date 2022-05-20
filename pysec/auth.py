from datetime import datetime
import sqlite3
from typing import List, Tuple
from . import basic, configs
SQLDefaultUserDBpath = configs.SQLDefaultUserDBpath
from abc import ABCMeta, abstractmethod
from . import globals

class user(metaclass=ABCMeta):
    _userName:str
    __key:bytes
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
    def __saveNewUser(self):
        pass
    @abstractmethod
    def gatData(self, __name: str) -> any:
        pass
    @abstractmethod
    def setData(self, __name: str, __value: any) -> None:
        pass
    @abstractmethod
    def decryptWithUserKey(self, data:str|bytes, sender:str) -> bytes:
        pass
    @abstractmethod
    def encryptWithUserKey(self, data:str|bytes, otherUsers:List[str]) -> bytes:
        pass
    @abstractmethod
    def generateNewKeys(self):
        pass

class standardUser(user):
    _userName:str = ""
    __key:bytes
    c:sqlite3.Cursor
    def __init__(self, userName:str) -> None:
        super().__init__()
        self.c:sqlite3.Cursor = SQLDefaultUserDBpath.cursor()
        self._userName = userName
        self.id = self.c.execute("SELECT id FROM users WHERE name=?", (userName,)).fetchone()
        if self.id == None:
            self.__saveNewUser()
            self.id = self.c.execute("SELECT id FROM users WHERE name=?", (userName,)).fetchone()
        
    def setData(self, __name: str, __value: any) -> None:
        self.c.execute(
            "DELETE FROM {id} WHERE key=?".format(self.id), (__name,)
        )
        self.c.execute(
            "INSERT INTO {id} VALUES (? ,?)".format(self.id),
            (__name, __value)
        )
        SQLDefaultUserDBpath.commit()
    
    def getData(self, __name: str) -> any:
        if __name == "__key":
            return self.__key
        result = self.c.execute(
            "SELECT value FROM {id} WHERE key=?".format(self.id), 
            (__name,)
        ).fetchone()
        if result == None:
            raise AttributeError()
        return result

    def delete(self):
        pass

    def login(self, pwd:str, mfaToken:int|None=None):
        keys = basic.kms()
        self.__key = keys.getKey(self.id, pwd)
        if datetime.now().year - datetime(self.getData("accountCreation")) > 2: # As specified in https://csrc.nist.gov/Projects/Key-Management/Key-Management-Guidelines
            self.generateNewKeys()
            self.setData("accountKeysCreation", datetime.now())

    def logout(self):
        pass
    
    def enableMFA(self):
        pass

    def disableMFA(self):
        pass

    def createOTP(self):
        pass
    
    def __saveNewUser(self):
        self.id = globals.base64encode(globals._getKey(self._userName), 32)
        keys = globals.createECCKey()
        self.pubKey = keys[0]
        self.privKey = keys[1]
        self.c.execute("CREATE TABLE {id} (key text, value blob)".format(self.id))
        self.c.execute("INSERT INTO pubKeys VALUES (?, ?)", (self.id, self.pubKey))
        self.setData("userPrivateKey", self.privKey)
        self.setData("userPublicKey", self.pubKey)
        self.setData("accountKeysCreation", datetime.now().year)

    def decryptWithUserKey(self, data:str|bytes, sender:str) -> bytes:
        key = globals.getSharedKey(self.privKey, sender)
        
    
    def encryptWithUserKey(self, data:str|bytes, otherUsers:List[str]) -> List[Tuple[str, bytes]]:
        AESKeys = [globals.getSharedKey(self.privKey, name) for name in otherUsers]
        results = [globals._restEncrypt(data, key) for key in AESKeys]
        for i in AESKeys: globals.zeromem(i)
        return zip(otherUsers, results)

    def generateNewKeys(self): # Both symetric and Public/Private 
        keys = globals.createECCKey()
        self.pubKey = keys[0]
        self.privKey = keys[1]
        self.c.execute("CREATE TABLE {id} (key text, value blob)".format(self.id))
        self.c.execute("INSERT INTO pubKeys VALUES (?, ?)", (self.id, self.pubKey))
        self.setData("userPrivateKey", self.privKey)
        self.setData("userPublicKey", self.pubKey)
        self.setData("accountKeysCreation", datetime.now().year)
