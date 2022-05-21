import os
import sqlite3
from . import configs
SQLDefaultCryptoDBpath:sqlite3.Connection = configs.SQLDefaultCryptoDBpath
SQLDefaultKeyDBpath:sqlite3.Connection = configs.SQLDefaultKeyDBpath
from .globals import _restEncrypt, _restDecrypt, zeromem, PBKDF2

class kms():
    def __cipher(self,text, pwd, salt):
        if self._masterHSM:
            pass
        else:
            key = PBKDF2(pwd, salt, 100000)
            r = _restEncrypt(text, key)
            zeromem(key)
            return r
 #Will also need to check the level of HSM: only master key or all keys. 
    def __decipher(self, ctext:str|bytes, pwd:str|bytes, salt):
        if self.hsmEnabled:
            pass
        else:
            key = PBKDF2(pwd, salt, 100000)
            r = _restDecrypt(ctext, key)
            zeromem(key)
            return r
    
    def __init__(self, keyDB:sqlite3.Connection=SQLDefaultKeyDBpath)->None:
        self.keydb = keyDB
        self.c = keyDB.cursor()
    
    def exportKeys(self):
        pass

    def importKeys(self):
        pass

    def getKey(self, name:str, pwd:str|bytes=None) -> bytes:
        self.c.execute("SELECT * FROM keys WHERE name == ?",(name,)) 
        key = self.c.fetchone()
        r = self.__decipher(key[1], pwd, key[2])
        return r

    def createNewKey(self, name:str, pwd:str|bytes=None) -> str:
        self.c.execute("SELECT * FROM keys WHERE name=?",(name,))
        if self.c.fetchone() != None:
            raise ValueError("Such a name already exists")
        k = os.urandom(32)
        s = os.urandom(12)
        k = self.__cipher(k, pwd, s)
        self.c.execute("INSERT INTO keys VALUES (?, ?, ?)", (name, k, s))
        self.keydb.commit()
        return k
    
    def removeKey(self, name:str, pwd:str|bytes=None) -> None:
        zeromem(self.getKey(name, pwd))
        self.c.execute("DELETE FROM crypto WHERE name=?", (name,))
        return

class crypto(kms):
    '''
    Ciphers and deciphers strings. Can also store strings securely and supports CRUD operations
    '''
    def __init__(self, keyDB:sqlite3.Connection=SQLDefaultCryptoDBpath):
        self.keydb = keyDB
        self.c = self.keydb.cursor()
        id = int(self.c.execute("SELECT MAX(id) FROM crypto").fetchone()[0])
        if id == None:
            self.id=1
        else:
            self.id = id
        super().__init__(self.keydb)
    
    def exportData(self):
        pass

    def importData(self):
        pass
    
    def secureCreate(self, data:bytes, pwd=None):
        id = self.id
        self.id+=1
        key = self.createNewKey(str(id), pwd)
        self.c.execute("INSERT INTO crypto VALUES (?, ?)",(id,self.__cipher(data)))
        zeromem(key)
        self.keydb.commit()
        return id
    
    def secureRead(self, id:int, pwd:str|bytes):
        self.c.execute("SELECT ctext FROM crypto WHERE id=?", (id,))
        ctext = self.c.fetchone()[0]
        if ctext == None:
            raise ValueError("Your selected data does not exists")
        key = self.getKey(str(id),pwd)
        text = self.__decipher(ctext,key)
        zeromem(key)
        return text
    
    def secureUpdate(self, id:int, new:str|bytes, pwd:str|bytes):
        zeromem(self.secureRead(id,pwd))
        key = self.getKey(str(id),pwd)
        ctext = self.__cipher(new, key)
        zeromem(key)
        self.c.execute("UPDATE crypto SET ctext=? WHERE id=?", (ctext, id))
        self.keydb.commit()
        return
    
    def secureDelete(self,id:int, pwd:str|bytes=None) -> None:
        zeromem(self.secureRead(id,pwd))
        self.c.execute("DELETE FROM crypto WHERE id=?",(id,))
        self.removeKey(str(id),pwd)
        self.keydb.commit()
        return
