from . import basic, _userDB
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

class admin(user):
    _userName:str = ""
    __key:bytes
    def __init__(self, userName:str) -> None:
        super().__init__()
        self.c = _userDB.cursor()
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
        _userDB.commit()
    
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
        self.key = keys.getKey(self.id, pwd)
        # Encrypt it with a session key and send the ciphertext in coockie to clinet
        # Delete decryption key after 15 mins 


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
        _userDB.commit()