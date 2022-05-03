from typing import List
from . import basic, userDB
from abc import ABCMeta, abstractmethod

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
    def __setattr__(self, __name: str, __value: any) -> None:
        pass
    @abstractmethod
    def __getattribute__(self, __name: str) -> any:
        pass
    @abstractmethod
    def decryptWithUserKey(self, data:str|bytes) -> bytes:
        pass
    @abstractmethod
    def encryptWithUserKey(self, data:str|bytes, otherUsers:List[str]) -> bytes:
        pass

class standardUser(user):
    _userName:str = ""
    __key:bytes
    def __init__(self, userName:str) -> None:
        super().__init__()
        self.c = userDB.cursor()
        self._userName = userName
        self.id = self.c.execute("SELECT id FROM users WHERE name=?", (userName,)).fetchone()
        if self.id == None:
            self.__saveNewUser()
            self.id = self.c.execute("SELECT id FROM users WHERE name=?", (userName,)).fetchone()
        
    def __setattr__(self, __name: str, __value: any) -> None:
        self.c.execute(
            "INSERT INTO {id} VALUES (? ,?)".format(self.id),
            (__name, __value)
        )
        userDB.commit()
    
    def __getattribute__(self, __name: str) -> any:
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

    def logout(self):
        pass
    
    def enableMFA(self):
        pass

    def disableMFA(self):
        pass

    def createOTP(self):
        pass
    
    def __saveNewUser(self):
        self.c.execute("CREATE TABLE {id} (key text, value blob)")
        userDB.commit()
    
    def encryptWithUserKey(self, data:str|bytes) -> bytes:
        pass

    def decryptWithUserKey(self, data:str|bytes) -> bytes:
        pass
    
    def encryptWithUserKey(self, data:str|bytes, otherUsers:List[str]) -> bytes:
        pass
