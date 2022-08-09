"""
Basic security related classes.
"""
from datetime import datetime
import os
from typing import ByteString
from sqlalchemy import select, func
from sqlalchemy.orm import Session, scoped_session
from . import configs, base, DBschemas
SQLDefaultCryptoDBpath:Session = configs.SQLDefaultCryptoDBpath
SQLDefaultKeyDBpath:Session = configs.SQLDefaultKeyDBpath
from .base import restEncrypt, restDecrypt, zeromem, PBKDF2

class KeyManagementError(Exception):
    """Error in Key Management System

    For example, compliance issues

    Arguments:
        Exception -- Inherits base Exception class
    """
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
        """Encrypt a string

        Arguments:
            text -- Plain text

            pwd -- Password

            salt -- Salt for hashing

            iterations -- Iterations for hashing

        Returns:
            Cipher text
        """
        if self._HSM:
            return None
        key = PBKDF2(pwd, salt, iterations) if iterations > 0 else pwd
        r = restEncrypt(text, key)
        zeromem(key)
        return r
    def _decipher(self, ctext:ByteString, pwd:ByteString, salt:bytes, iterations:int):
        """Decrypt a string

        Arguments:
            ctext -- Cipher text

            pwd -- Password

            salt -- Salt for Hashing

            iterations -- Iterations for hashing

        Returns:
            Plaintext
        """
        if self._HSM:
            return None
        key = PBKDF2(pwd, salt, iterations) if iterations > 0 else pwd
        r = restDecrypt(ctext, key)
        zeromem(key)
        return r

    def __init__(self, keyDB:Session=scoped_session(SQLDefaultKeyDBpath))->None:
        """The title says it all"""
        self.c:Session = keyDB
        self._HSM = False

    def getKey(self, name:str, pwd:ByteString=None, force:bool=False) -> bytes:
        """Get a Key

        Arguments:
            name -- Name of the key to get

        Keyword Arguments:
            pwd -- Password (default: {None})

            force -- Override Cryptoperiod Compliance errors (default: {False})

        Raises:
            ValueError: If the key does not exist

            KeyManagementError: If the key has expired - set force=True to override

            ValueError: If an unsupported cipher is used

            ValueError: Wrong passwords were provided or the key was tampered with

        Returns:
            The key as python bytes
        """
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
        """Create a new key and store it

        Arguments:
            name -- Name of the Key

        Keyword Arguments:
            pwd -- Password (default: {None})

        Raises:
            KeyError: If key with same name already exists

        Returns:
            The key as python bytes
        """
        year = datetime.today().year
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
        self.c.flush()
        self.c.commit()
        return k

    def removeKey(self, name:str, pwd:ByteString=None) -> None:
        """Delete a Key

        Arguments:
            name -- Name of the Key

        Keyword Arguments:
            pwd -- Password (default: {None})
        """
        zeromem(self.getKey(name, pwd, True))
        stmt = select(DBschemas.KeysTable).where(DBschemas.KeysTable.name == name).limit(1)
        key:DBschemas.KeysTable = self.c.scalar(stmt)
        self.c.delete(key)
        self.c.flush()
        self.c.commit()
        return
    
    def __del__(self):
        self.c.close()

class Crypto(KMS):
    '''
    Crypto Class (see Documentation)
    '''
    def __init__(self, keyDB:Session=scoped_session(SQLDefaultCryptoDBpath)):
        """The title says it all"""
        self.c:scoped_session = keyDB
        stmt = select(func.max(DBschemas.CryptoTable.id))
        self.num = self.c.scalar(stmt)
        super().__init__(self.c)

    def secureCreate(self, data:ByteString, pwd:ByteString=None, _num:int=None):
        """Store Encrypted Data

        Arguments:
            data -- Plaintext data

        Keyword Arguments:
            pwd -- Password To Decrypt (default: {None})

            _num -- Not good idea to set! Id to store in DB (default: {None})

        Returns:
            Integer to be passed to secureRead to return data
        """
        if _num is None:
            self.num+=1
            _num = self.num
        key = self.createNewKey(str(_num), pwd)
        salt = os.urandom(12)
        keyOb = DBschemas.CryptoTable(
            id = _num,
            ctext = self._cipher(data, key, salt, 0),
            salt = salt,
            cipher = configs.defaultAlgorithm,
            saltIter = configs.defaultIterations
        )
        self.c.add(keyOb)
        zeromem(key)
        self.c.flush()
        self.c.commit()
        return _num

    def secureRead(self,num:int, pwd:ByteString):
        """Read data from secureCreate

        Arguments:
            num -- Integer returned from secureCreate

            pwd -- Password set in secureCreate

        Returns:
            Plaintext data
        """
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
        """Update Entry Set by secureCreate

        Arguments:
            num -- Integer id of entry

            new -- New data to set

            pwd -- Password
        """
        self.secureDelete(num, pwd)
        self.secureCreate(new, pwd, num)

    def secureDelete(self, num:int, pwd:ByteString=None) -> None:
        """Delete Data set by secureCreate

        Arguments:
            num -- Integer id of entry

        Keyword Arguments:
            pwd -- Password (default: {None})
        """
        zeromem(self.getKey(str(num), pwd, True))
        stmt = select(DBschemas.CryptoTable).where(DBschemas.CryptoTable.id == num)
        key:DBschemas.CryptoTable = self.c.scalar(stmt)
        self.c.delete(key)
        self.c.flush()
        self.removeKey(str(num), pwd)
