import os
import sqlite3
from . import configs
SQLDefaultCryptoDBpath:sqlite3.Connection = configs.SQLDefaultCryptoDBpath
SQLDefaultKeyDBpath:sqlite3.Connection = configs.SQLDefaultKeyDBpath
from .base import _restEncrypt, _restDecrypt, zeromem, PBKDF2

class kms():
    def _cipher(self, text:str|bytes, pwd:str|bytes, salt:bytes, iter:int):
        if self._HSM:
            pass
        else:
            key = PBKDF2(pwd, salt, iter)
            r = _restEncrypt(text, key)
            zeromem(key)
            return r
 #Will also need to check the level of HSM: only master key or all keys. 
    def _decipher(self, ctext:str|bytes, pwd:str|bytes, salt:bytes, iter:int):
        if self._HSM:
            pass
        else:
            key = PBKDF2(pwd, salt, iter)
            r = _restDecrypt(ctext, key)
            zeromem(key)
            return r
    
    def __init__(self, keyDB:sqlite3.Connection=SQLDefaultKeyDBpath)->None:
        self.keydb = keyDB
        self.c = keyDB.cursor()
        self._HSM = False
    
    def exportKeys(self):
        pass

    def importKeys(self):
        pass

    def getKey(self, name:str, pwd:str|bytes=None) -> bytes:
        self.c.execute("SELECT * FROM keys WHERE name == ?",(name,)) 
        key = self.c.fetchone()
        if key[3] != configs.defaultAlgorithm:
            raise ValueError("Unsupported Cipher") # This source code can be extended to support other ciphers also 
        r = self._decipher(key[1], pwd, key[2], key[4])
        return r

    def createNewKey(self, name:str, pwd:str|bytes=None) -> str:
        self.c.execute("SELECT * FROM keys WHERE name==?",(name,))
        if self.c.fetchone() != None:
            raise ValueError("Such a name already exists")
        k = os.urandom(32)
        s = os.urandom(12)
        ek = self._cipher(k, pwd, s, configs.defaultIterations)
        self.c.execute
        (
            "INSERT INTO keys VALUES (?, ?, ?, ?, ?)", 
            (name, ek, s, 
            configs.defaultAlgorithm, configs.defaultIterations
            )
        )
        self.keydb.commit()
        return k
    
    def removeKey(self, name:str, pwd:str|bytes=None) -> None:
        zeromem(self.getKey(name, pwd))
        self.c.execute("DELETE FROM keys WHERE name=?", (name,))
        return

class crypto(kms):
    '''
    Ciphers and deciphers strings. Can also store strings securely and supports CRUD operations
    '''
    def __init__(self, keyDB:sqlite3.Connection=SQLDefaultCryptoDBpath):
        self.keydb = keyDB
        self.c = self.keydb.cursor()
        id = int(self.c.execute("SELECT MAX(id) FROM crypto").fetchone()[0])
        self.id = id
        super().__init__(self.keydb)
    
    def exportData(self):
        pass

    def importData(self):
        pass
    
    def secureCreate(self, data:bytes, pwd:str|bytes=None, id:int=None):
        if id == None:
            self.id+=1
            id = self.id
        key = self.createNewKey(str(id), pwd)
        salt = os.urandom(12)
        self.c.execute
        (
            "INSERT INTO crypto VALUES (?, ?, ?, ?, ?)",(id, 
            self._cipher(data, key, salt, 0), 
            salt, configs.defaultAlgorithm, 
            self.c.execute("SELECT MAX(id) FROM crypto").fetchone()[0])
        )
        zeromem(key)
        self.keydb.commit()
        return id
    
    def secureRead(self, id:int, pwd:str|bytes):
        self.c.execute("SELECT * FROM crypto WHERE id==?", (id,))
        ctext = self.c.fetchone()
        if ctext == None:
            raise ValueError("Your selected data does not exists")
        key = self.getKey(str(id),pwd)
        text = self._decipher(ctext[1], key, ctext[2], 0)
        zeromem(key)
        return text
    
    def secureUpdate(self, id:int, new:str|bytes, pwd:str|bytes):
        self.secureDelete(id, pwd)
        self.secureCreate(new, pwd, id)
        return
    
    def secureDelete(self,id:int, pwd:str|bytes=None) -> None:
        zeromem(self.getKey(id,pwd))
        self.c.execute("DELETE FROM crypto WHERE id=?",(id,))
        self.removeKey(str(id),pwd)
        self.keydb.commit()
        return
