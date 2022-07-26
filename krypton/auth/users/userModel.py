"""
Provides User Models
Note for developer's working on Krypton: this only contains user model cryptography.
"""

import datetime
import os
import pickle
from typing import ByteString
from sqlalchemy import delete, select

from krypton.auth import factors
from ... import DBschemas, configs
from ... import base
from .userModelBaseAuth import AuthUser
from .userModelMFAAuth import MFAUser
from .bases import UserError, userExistRequired, user

class standardUser(AuthUser, MFAUser, user):
    """User Model for Krypton
    Please pass None to __init__ to create a new user, after that call saveNewUser with required args.
    """
    userName:str
    _key:bytes
    salt:bytes
    sessionKey:bytes
    saved:bool
    loggedin:bool
    backupKeys:list[str] = []
    backupAESKeys:list[bytes] = []
    
    def __init__(self, userName:str=None, userID:int=None) -> None:
        super().__init__()
        self.loggedin = False
        self.c = configs.SQLDefaultUserDBpath
        if userID is None and userName is not None:
            userID = select(DBschemas.UserTable.id).where(DBschemas.UserTable.name == userName)
            userID = configs.SQLDefaultUserDBpath.scalar(userID)
            if userID is None:
                raise UserError("This user does not exist.")
        if userID is None and userName is None:
            self.saved = False
            return
        self.id = userID
        stmt = select(DBschemas.UserTable.name).where(DBschemas.UserTable.id == userID).limit(1)
        self.userName = self.c.scalar(stmt)
        self.saved = True
        if self.userName is None:
            self.saved = False

    @userExistRequired
    def setData(self, name: str, value: any) -> None:
        """Store user data as a key-value pair

        Arguments:
            name -- key

            value -- value
        """
        try:
            self.deleteData(name)
        except:
            pass
        entry = DBschemas.UserData(
            Uid = self.id,
            name = name,
            value = base.restEncrypt(value, self._key)
        )
        self.c.add(entry)
        self.c.commit()

    @userExistRequired
    def getData(self, name: str) -> ByteString:
        """Get value set by setData

        Arguments:
            name -- the key

        Raises:
            AttributeError: if a value is not set

        Returns:
            The value
        """
        stmt = select(DBschemas.UserData.value).where(DBschemas.UserData.name == name
            and DBschemas.UserData.Uid == self.id)
        result = self.c.scalar(stmt)
        # Don't forget to check backuped keys to decrypt data
        if result is None:
            raise AttributeError()
        try: text = base.restDecrypt(result, self._key)
        except ValueError: pass
        for key in self.backupAESKeys:
            flag = False
            try: text = base.restDecrypt(result, self._key)
            except ValueError: flag = True
            if flag is not False:
                break
        return text

    @userExistRequired
    def deleteData(self, name:str) -> None:
        """Delete key-value pair set by setData

        Arguments:
            name -- The key to remove
        """
        stmt = delete(DBschemas.UserData).where(DBschemas.UserData.name == name
            and DBschemas.UserData.Uid == self.id)
        self.c.execute(stmt)

    @userExistRequired
    def decryptWithUserKey(self, data:ByteString, salt:bytes=None, sender=None) -> bytes:
        """Decrypt data with user's key

        Arguments:
            data -- Ciphertext

            salt -- Salt

        Keyword Arguments:
            sender -- If applicable sender's user name (default: {None})

        Returns:
            Plaintext
        """
        # Will also need to check the backup keys if decryption fails
        if salt is None and sender is None:
            try: text = base.restDecrypt(data, self._key)
            except ValueError: pass
            for key in self.backupAESKeys:
                flag = False
                try: text = base.restDecrypt(data, key)
                except ValueError: flag = True
                if flag is not False:
                    break
            return text
        key = base.getSharedKey(self._privKey, sender, salt)
        try: text = base.restDecrypt(data, key)
        except ValueError: pass
        for key in self.backupKeys:
            key = base.getSharedKey(key, sender, salt)
            flag = False
            try: text = base.restDecrypt(data, key)
            except ValueError: flag = True
            if flag is not False:
                break
        return text

    @userExistRequired
    def encryptWithUserKey(self, data:ByteString, otherUsers:list[str]=None) -> list[tuple[str, bytes, bytes]]:
        """Encrypt data with user's key

        Arguments:
            data -- Plaintext

        Keyword Arguments:
            otherUsers -- List of user names of people who can decrypt it  (default: {None})

        Returns:
            If otherUsers is None: ciphertext.
            If otherUsers is not None: list of tuples of form (user name, ciphertext, salt), which needs to be provided so that user name's user can decrypt it.
        """
        if otherUsers is None:
            ctext =  base.restEncrypt(data, self._key)
            return ctext
        salts = [os.urandom(12) for name in otherUsers]
        AESKeys = [base.getSharedKey(self._privKey, name, salts[i])
            for i, name in enumerate(otherUsers)]
        results = [base.restEncrypt(data, key) for key in AESKeys]
        for i in AESKeys: base.zeromem(i)
        return list(zip(otherUsers, results, salts))

    @userExistRequired
    def shareSet(self, name:str, data:ByteString, otherUsers:list[str]) -> None:
        keys = self.encryptWithUserKey(data, otherUsers)
        ids = [self.c.scalar(select(DBschemas.UserTable.id)
            .where(DBschemas.UserTable.name == user)) 
            for user in otherUsers]
        for i, key in enumerate(keys):
            row = DBschemas.UserShareTable(
                sender = self.userName,
                name = name,
                salt = key[2],
                value = key[1],
                shareUid = ids[i]
            )
            self.c.add(row)
        self.c.commit()

    @userExistRequired
    def shareGet(self, name:str) -> bytes:
        stmt = select(DBschemas.UserShareTable).where(DBschemas.UserShareTable.name == name 
            and DBschemas.UserShareTable.shareUid == self.id)
        row:DBschemas.UserShareTable = self.c.scalar(stmt)
        return self.decryptWithUserKey(row.value, row.salt, row.sender)
    
    @userExistRequired
    def generateNewKeys(self, pwd:str):
        """Regenerate Encryption keys

        Arguments:
            pwd -- Password
        """
        keys = base.createECCKey()
        backups = self.getData("_backupKeys")
        backupList:list[bytes] = pickle.loads(backups)
        backupList.append(self._privKey)
        self.setData("_backupKeys", pickle.dumps(backupList))
        for x in backups: base.zeromem(x)
        base.zeromem(backups)
        backups = self.getData("_backupAESKeys")
        backupList:list[bytes] = pickle.loads(backups)
        backupList.append(self._key)
        self.setData("_backupAESKeys", pickle.dumps(backupList))
        for x in backups: base.zeromem(x)
        base.zeromem(backups)
        tag = factors.password.getAuth(pwd)
        row = self.c.query(DBschemas.UserTable).where(DBschemas.UserTable.id == self.id).get(1)
        row.pwdAuthToken = tag
        self.c.commit()
        self._key = factors.password.auth(tag, pwd)
        self._privKey = keys[0]
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
        self.setData("_userPrivateKey", self._privKey)
        self.setData("_userPublicKey", self.pubKey)
        self.setData("_accountKeysCreation", datetime.now().year)

    @userExistRequired
    def reload(self):
        """Reload encryption keys. Warning: previous keys are not purged!
        """
        _privKey = self.getData("_userPrivateKey")
        pubKey = self.getData("_userPublicKey")
        self._privKey = _privKey.decode()
        self.pubKey = pubKey.decode()
        base.zeromem(_privKey)
        self.backupAESKeys = pickle.loads(self.getData("_backupAESKeys"))
        self.backupKeys = pickle.loads(self.getData("_backupKeys"))
