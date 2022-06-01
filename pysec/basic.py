import os
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from datetime import date, datetime
from . import configs, base, DBschemas
SQLDefaultCryptoDBpath:Session = configs.SQLDefaultCryptoDBpath
SQLDefaultKeyDBpath:Session = configs.SQLDefaultKeyDBpath
from .base import _restEncrypt, _restDecrypt, zeromem, PBKDF2

class KeyManagementError(Exception):
    def __init__(self, *args: object) -> None:
        self.message = args[0]
    def __str__(self) -> str:
        return self.message

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
    
    def __init__(self, keyDB:Session=SQLDefaultKeyDBpath)->None:
        self.c:Session = keyDB
        self._HSM = False
    
    def exportKeys(self):
        pass

    def importKeys(self):
        pass

    def getKey(self, name:str, pwd:str|bytes=None, force:bool=False) -> bytes:
        stmt = select(DBschemas.keysTable).where(DBschemas.keysTable.name == name).limit(1)
        key:DBschemas.keysTable = self.c.scalar(stmt)
        if key == None:
            raise ValueError("Such key does not exist")
        if datetime.now().year - key.year >= configs.defaultCryptoperiod and not force:
            raise KeyManagementError("This key has expired. Please add force to the argument to retrieve it anyway. Please update or remove/create the key to regenerate a new one.")
        if key.cipher != configs.defaultAlgorithm:
            raise ValueError("Unsupported Cipher") # This source code can be extended to support other ciphers also 
        r = self._decipher(key.key, pwd, key.salt, key.saltIter)
        if r[-1] != 36: ## Problem
            raise ValueError("Wrong passwords have been provided.")
        return base.base64decode(r[:-1])
        

    def createNewKey(self, name:str, pwd:str|bytes=None) -> str:
        if len(name) > 20:
            raise ValueError("Name must be less then 20 characters long")
        now = 100
        stmt = select(DBschemas.keysTable).where(DBschemas.keysTable.name == "name")
        a = True
        try: self.c.scalars(stmt).one()
        except: a=False
        finally: 
            if a: raise KeyError("Such a name already exists")
        k = os.urandom(32)
        s = os.urandom(12)
        rebased = base.base64encode(k)
        editedRebased = rebased+"$"
        ek = self._cipher(editedRebased, pwd, s, configs.defaultIterations)
        zeromem(rebased)
        zeromem(editedRebased)
        key = DBschemas.keysTable(
            name = name,
            key = ek,
            salt = s,
            cipher = configs.defaultAlgorithm,
            saltIter = configs.defaultIterations,
            year = now
        )
        self.c.add(key)
        self.c.commit()
        return k
    
    def removeKey(self, name:str, pwd:str|bytes=None) -> None:
        zeromem(self.getKey(name, pwd, True))
        stmt = select(DBschemas.keysTable).where(DBschemas.keysTable.name == name).limit(1)
        key:DBschemas.keysTable = self.c.scalar(stmt)
        self.c.delete(key)
        self.c.commit()
        return

class crypto(kms):
    '''
    Ciphers and deciphers strings. Can also store strings securely and supports CRUD operations
    '''
    def __init__(self, keyDB:Session=SQLDefaultCryptoDBpath):
        self.c:Session = keyDB
        stmt = select(func.max(DBschemas.cryptoTable.id))
        self.id = self.c.scalar(stmt)
        super().__init__(self.c)
    
    def exportData(self):
        pass

    def importData(self):
        pass
    
    def secureCreate(self, data:bytes, pwd:str|bytes=None, id:int=None):
        if id == None:
            self.id+=1
        key = self.createNewKey(str(self.id), pwd)
        salt = os.urandom(12)
        keyOb = DBschemas.cryptoTable(
            id = self.id,
            ctext = self._cipher(data, key, salt, 0),
            salt = salt,
            cipher = configs.defaultAlgorithm,
            saltIter = configs.defaultIterations
        )
        self.c.add(keyOb)
        zeromem(key)
        self.c.commit()
        return self.id
    
    def secureRead(self, id:int, pwd:str|bytes):
        stmt = select(DBschemas.cryptoTable).where(DBschemas.cryptoTable.id == id).limit(1)
        ctext = self.c.scalar(stmt)
        reset = False
        try: key = self.getKey(str(id), pwd)
        except KeyManagementError:
            reset = True
            key = self.getKey(str(id), pwd, True)
        text = self._decipher(ctext.ctext, key, ctext.salt, 0)
        if reset:
            self.secureUpdate(id, text, pwd)
        zeromem(key)
        return text
    
    def secureUpdate(self, id:int, new:str|bytes, pwd:str|bytes):
        self.secureDelete(id, pwd)
        self.secureCreate(new, pwd, id)
        return
    
    def secureDelete(self,id:int, pwd:str|bytes=None) -> None:
        zeromem(self.getKey(str(id), pwd, True))
        stmt = select(DBschemas.cryptoTable).where(DBschemas.cryptoTable.id == id)
        key:DBschemas.cryptoTable = self.c.scalar(stmt)
        self.c.delete(key)
        self.removeKey(str(id),pwd)
        return
