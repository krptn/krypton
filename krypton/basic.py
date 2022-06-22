"""
Basic security related classes.
"""
from datetime import datetime
import os
from typing import ByteString
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from . import configs, base, DBschemas
SQLDefaultCryptoDBpath:Session = configs.SQLDefaultCryptoDBpath
SQLDefaultKeyDBpath:Session = configs.SQLDefaultKeyDBpath
from .base import _restEncrypt, _restDecrypt, zeromem, PBKDF2

class KeyManagementError(Exception):
    """Exception to be raised on error in KMS"""
    def __init__(self, *args: object) -> None:
        self.message = args[0]
        super().__init__()
    def __str__(self) -> str:
        return self.message

class KMS():
    """
    They Key Management System
    """
    def _cipher(self, text:ByteString, pwd:ByteString, salt:bytes, iterations:int):
        """The title says it all"""
        if self._HSM:
            return None
        key = PBKDF2(pwd, salt, iterations) if iterations > 0 else pwd
        r = _restEncrypt(text, key)
        zeromem(key)
        return r
    def _decipher(self, ctext:ByteString, pwd:ByteString, salt:bytes, iterations:int):
        """The title says it all"""
        if self._HSM:
            return None
        key = PBKDF2(pwd, salt, iterations) if iterations > 0 else pwd
        r = _restDecrypt(ctext, key)
        zeromem(key)
        return r

    def __init__(self, keyDB:Session=SQLDefaultKeyDBpath)->None:
        """The title says it all"""
        self.c:Session = keyDB
        self._HSM = False

    def getKey(self, name:str, pwd:ByteString=None, force:bool=False) -> bytes:
        """The title says it all"""
        stmt = select(DBschemas.KeysTable).where(DBschemas.KeysTable.name == name).limit(1)
        key:DBschemas.KeysTable = self.c.scalar(stmt)
        if key is None:
            raise ValueError("Such key does not exist")
        if datetime.now().year - key.year >= configs.defaultCryptoperiod and not force:
            raise KeyManagementError("This key has expired. Please add force to the argument to retrieve it anyway.")
        if key.cipher != configs.defaultAlgorithm:
            raise ValueError("Unsupported Cipher")
        r = self._decipher(key.key, pwd, key.salt, key.saltIter)
        splited = r.split(b"$")
        if splited[1] != name.encode() or splited[2] != str(key.year).encode(): ## Problem
            raise ValueError("Wrong passwords have been provided or the database has been tampered with.")
        result = base.base64decode(splited[0])
        zeromem(r)
        zeromem(splited[0])
        return result


    def createNewKey(self, name:str, pwd:ByteString=None) -> str:
        """The title says it all"""
        year = datetime.today().year
        if len(name) > 20:
            raise ValueError("Name must be less then 20 characters long")
        stmt = select(DBschemas.KeysTable).where(DBschemas.KeysTable.name == "name")
        a = True
        try:
            self.c.scalars(stmt).one()
        except:
            a=False
        finally:
            if a: raise KeyError("Such a name already exists")
        k = os.urandom(32)
        s = os.urandom(12)
        rebased = base.base64encode(k)
        editedRebased = rebased+f"${name}${year}"
        ek = self._cipher(editedRebased, pwd, s, configs.defaultIterations)
        zeromem(rebased)
        zeromem(editedRebased)
        key = DBschemas.KeysTable(
            name = name,
            key = ek,
            salt = s,
            cipher = configs.defaultAlgorithm,
            saltIter = configs.defaultIterations,
            year = year
        )
        self.c.add(key)
        self.c.commit()
        return k

    def removeKey(self, name:str, pwd:ByteString=None) -> None:
        """The title says it all"""
        zeromem(self.getKey(name, pwd, True))
        stmt = select(DBschemas.KeysTable).where(DBschemas.KeysTable.name == name).limit(1)
        key:DBschemas.KeysTable = self.c.scalar(stmt)
        self.c.delete(key)
        self.c.commit()
        return

class Crypto(KMS):
    '''
    Crypto Class (see Documentation)
    '''
    def __init__(self, keyDB:Session=SQLDefaultCryptoDBpath):
        """The title says it all"""
        self.c:Session = keyDB
        stmt = select(func.max(DBschemas.CryptoTable.id))
        self.num = self.c.scalar(stmt)
        super().__init__(self.c)

    def secureCreate(self, data:bytes, pwd:ByteString=None, num:int=None):
        """The title says it all"""
        if num is None:
            self.num+=1
        key = self.createNewKey(str(self.num), pwd)
        salt = os.urandom(12)
        keyOb = DBschemas.CryptoTable(
            id = self.num,
            ctext = self._cipher(data, key, salt, 0),
            salt = salt,
            cipher = configs.defaultAlgorithm,
            saltIter = configs.defaultIterations
        )
        self.c.add(keyOb)
        zeromem(key)
        self.c.commit()
        return self.num

    def secureRead(self,num:int, pwd:ByteString):
        """The title says it all"""
        stmt = select(DBschemas.CryptoTable).where(DBschemas.CryptoTable.id ==num).limit(1)
        ctext = self.c.scalar(stmt)
        reset = False
        try:
            key = self.getKey(str(num), pwd)
        except KeyManagementError:
            reset = True
            key = self.getKey(str(num), pwd, True)
        text = self._decipher(ctext.ctext, key, ctext.salt, 0)
        if reset:
            self.secureUpdate(num, text, pwd)
        zeromem(key)
        return text

    def secureUpdate(self, num:int, new:ByteString, pwd:ByteString):
        """The title says it all"""
        self.secureDelete(num, pwd)
        self.secureCreate(new, pwd, num)

    def secureDelete(self, num:int, pwd:ByteString=None) -> None:
        """The title says it all"""
        zeromem(self.getKey(str(num), pwd, True))
        stmt = select(DBschemas.CryptoTable).where(DBschemas.CryptoTable.id == num)
        key:DBschemas.CryptoTable = self.c.scalar(stmt)
        self.c.delete(key)
        self.removeKey(str(num), pwd)
