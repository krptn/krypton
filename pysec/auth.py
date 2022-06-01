from datetime import datetime
from sqlalchemy import select, text
from . import DBschemas, basic, configs
SQLDefaultUserDBpath = configs.SQLDefaultUserDBpath
from abc import ABCMeta, abstractmethod
from . import base
import os 
import pickle

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
    def encryptWithUserKey(self, data:str|bytes, otherUsers:list[str]) -> bytes:
        pass
    @abstractmethod
    def generateNewKeys(self):
        pass
    @abstractmethod
    def resetPWD(self):
        pass

class standardUser(user):
    _userName:str = ""
    __key:bytes
    saved = True
    logedin = False
    keys:basic.kms
    def __init__(self, userName:str) -> None:
        super().__init__()
        self.c = SQLDefaultUserDBpath
        self._userName = userName
        stmt = select(DBschemas.userTable.id).where(DBschemas.userTable.name == userName).limit(1)
        try: self.id = self.c.scalar(stmt)[0]
        except:
            self.saved = False
            stmt = select(DBschemas.userTable.id).where(DBschemas.userTable.name == userName).limit(1)
            self.id = self.c.scalar(stmt)[0]
        
    def setData(self, __name: str, __value: any) -> None:
        self.c.execute(
            text("INSERT INTO :id VALUES (:name, :value)"),
            {"id":self.id, "name":__name, "value":__value}
        )
        SQLDefaultUserDBpath.commit()
    
    def getData(self, __name: str) -> any:
        result = self.c.scalar(
            text("SELECT value FROM :id WHERE key=:name"), 
            {"name":__name, "id":self.id}
        ).value # Don't forget to check backuped keys to decrypt data 
        if result == None:
            raise AttributeError()
        return result

    def delete(self):
        pass

    def login(self, pwd:str, mfaToken:int|None=None):
        self.keys = basic.kms(SQLDefaultUserDBpath)
        try: self.__key = self.keys.getKey(self.id, pwd)
        except: self.generateNewKeys()
        self.logedin = True

    def logout(self):
        pass

    def resetPWD(self):
        pass
    
    def enableMFA(self):
        pass

    def disableMFA(self):
        pass

    def createOTP(self):
        pass
    
    def saveNewUser(self):
        if self.saved:
            raise ValueError("This user is already saved.")
        salt = os.urandom(12)
        self.id = base.base64encode(base.PBKDF2(self._userName, salt, configs.defaultIterations))
        keys = base.createECCKey()
        self.pubKey = keys[0]
        self.__privKey = keys[1]
        self.c.execute("CREATE TABLE {id} (key text, value blob)".format(self.id))
        key = DBschemas.pubKeyTable(
            name = self.id,
            key = self.pubKey
        )
        self.c.add(key)
        self.setData("userPrivateKey", self.__privKey)
        self.setData("userPublicKey", self.pubKey)
        self.setData("userSalt", salt)
        self.setData("backupKeys", pickle.dumps([]))
        self.setData("backupAESKeys", pickle.dumps([]))

    def decryptWithUserKey(self, data:str|bytes, sender:str) -> bytes: # Will also need to check the backup keys if decryption fails
        key = base.getSharedKey(self.__privKey, sender)
        
    
    def encryptWithUserKey(self, data:str|bytes, otherUsers:list[str]) -> list[tuple[str, bytes, bytes]]:
        salts = [os.urandom(12) for name in otherUsers]
        AESKeys = [base.getSharedKey(self.__privKey, name, salts[i], configs.defaultIterations) 
            for i, name in enumerate(otherUsers)]
        results = [base._restEncrypt(data, key) for key in AESKeys]
        for i in AESKeys: base.zeromem(i)
        return zip(otherUsers, results, salts)

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
        stmt = select(DBschemas.pubKeyTable).where(DBschemas.pubKeyTable.name == self.id)
        stmt = self.c.scalar(stmt)
        self.c.delete(stmt)
        key = DBschemas.pubKeyTable(
            name = self.id,
            key = self.pubKey
        )
        self.c.add(key)
        self.setData("userPrivateKey", self.__privKey)
        self.setData("userPublicKey", self.pubKey)
        self.setData("accountKeysCreation", datetime.now().year)
