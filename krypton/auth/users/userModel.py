"""
Provides User Models
Note for developer's working on Krypton: this only contains user model cryptography.
"""

#pylint: disable=no-member
#pylint: disable=attribute-defined-outside-init

import datetime
import os
import pickle
from typing import ByteString
from sqlalchemy import and_, delete, select, update
from sqlalchemy.orm import scoped_session

from .. import factors
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
    _privKey:bytes
    salt:bytes
    sessionKey:bytes
    saved:bool
    loggedin:bool
    backupKeys:list[str]
    backupAESKeys:list[bytes]

    def __init__(self, userName:str=None, userID:int=None) -> None:
        super().__init__()
        self.backupAESKeys = []
        self.backupKeys = []
        self.loggedin = False
        self.FIDORequired = False
        self.c = scoped_session(configs.SQLDefaultUserDBpath)
        if userID is None and userName is None:
            self.saved = False
            return
        if userName is not None:
            stmt = select(DBschemas.UserTable.id).where(DBschemas.UserTable.name == userName)
            self.id = self.c.scalar(stmt)
            self.userName = userName
            if self.id is None:
                raise UserError("This user does not exist.")
        else: # that is userID is not None
            stmt = select(DBschemas.UserTable.name).where(DBschemas.UserTable.id == userID).limit(1)
            self.userName = self.c.scalar(stmt)
            self.id = userID
            if self.userName is None:
                raise UserError("This user does not exist.")
        self.saved = True

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
        self.c.flush()
        self.c.commit()

    @userExistRequired
    def getData(self, name: str) -> ByteString:
        """Get value set by setData

        Arguments:
            name -- the key

        Raises:
            AttributeError: if a value is not set

            ValueError: if decryption fails

        Returns:
            The value
        """
        stmt = select(DBschemas.UserData.value).where(and_(DBschemas.UserData.name == name,
            DBschemas.UserData.Uid == self.id))
        result = self.c.scalar(stmt)
        if result is None:
            raise AttributeError()
        try:
            text = base.restDecrypt(result, self._key)
        except ValueError:
            pass
        for key in self.backupAESKeys:
            retry = False
            try:
                text = base.restDecrypt(result, key)
            except ValueError:
                retry = True
            if not retry:
                break
        try: return text
        except NameError as exc:
            raise ValueError("Unable to decrypt the cipertext") from exc

    @userExistRequired
    def deleteData(self, name:str) -> None:
        """Delete key-value pair set by setData

        Arguments:
            name -- The key to remove
        """
        stmt = delete(DBschemas.UserData).where(and_(DBschemas.UserData.name == name,
            DBschemas.UserData.Uid == self.id))
        self.c.execute(stmt)
        self.c.flush()
        self.c.commit()

    @userExistRequired
    def decryptWithUserKey(self, data:ByteString, salt:bytes=None, sender=None) -> bytes:
        """Decrypt data with user's key

        Arguments:
            data -- Ciphertext

            salt -- Salt

        Keyword Arguments:
            sender -- If applicable sender's user name (default: {None})

        Raises:
            ValueError: if decryption fails

        Returns:
            Plaintext
        """
        # Will also need to check the backup keys if decryption fails
        if salt is None and sender is None:
            try:
                text = base.restDecrypt(data, self._key)
            except ValueError:
                pass
            for key in self.backupAESKeys:
                retry = False
                try:
                    text = base.restDecrypt(data, key)
                except ValueError:
                    retry = True
                if not retry:
                    break
            return text
        if not isinstance(sender, int):
            stmt = select(DBschemas.UserTable.id).where(DBschemas.UserTable.name == sender)
            Uid = self.c.scalar(stmt)
        else:
            Uid = sender
        keys = base.getSharedKey(self._privKey, Uid, salt)
        try:
            for key in keys:
                retry = False
                try:
                    text = base.restDecrypt(data, key)
                except ValueError:
                    retry = True
                base.zeromem(key)
                if not retry:
                    break
        except ValueError: pass
        for privKey in self.backupKeys:
            keys = base.getSharedKey(privKey, Uid, salt)
            retry = False
            for key in keys:
                try:
                    text = base.restDecrypt(data, key)
                except ValueError:
                    retry = True
                base.zeromem(key)
                if not retry:
                    break
            if not retry:
                break
        try: return text
        except NameError as exc:
            raise ValueError("Unable to decrypt the cipertext") from exc

    @userExistRequired
    def encryptWithUserKey(self, data:ByteString, otherUsers:list[int]=None) -> list[tuple[str, bytes, bytes]]:
        """Encrypt data with user's key

        Arguments:
            data -- Plaintext

        Keyword Arguments:
            otherUsers -- List of user names of people who can decrypt it  (default: {None})

        Returns:
            If otherUsers is None: ciphertext.
            If otherUsers is not None: list of tuples of form (user name, ciphertext, salt), which needs to be provided so that username's user can decrypt it.
        """
        # pylint: disable=expression-not-assigned
        if otherUsers is None:
            ctext =  base.restEncrypt(data, self._key)
            return ctext
        salts = [os.urandom(12) for i in otherUsers]
        AESKeys = []
        otherUsers = [
            self.c.scalar(
                select(DBschemas.UserTable.id).where(DBschemas.UserTable.name == name)
            ) 
            for name in otherUsers
        ]
        for i, Uid in enumerate(otherUsers):
            temp = base.getSharedKey(self._privKey, Uid, salts[i])
            [base.zeromem(x) for x in temp[1:]]
            AESKeys.append(temp[0])
        results = [base.restEncrypt(data, key) for key in AESKeys]
        [base.zeromem(x) for x in AESKeys]
        return list(zip(otherUsers, results, salts))

    @userExistRequired
    def shareSet(self, name:str, data:ByteString, otherUsers:list[str]) -> None:
        """Set data readable by others

        Arguments:
            name -- The "name" of the data

            data -- The data

            otherUsers -- List of usernames who should read it
        """
        keys = self.encryptWithUserKey(data, otherUsers)
        ids = [self.c.scalar(select(DBschemas.UserTable.id)
            .where(DBschemas.UserTable.name == user))
            for user in otherUsers]
        for i, key in enumerate(keys):
            row = DBschemas.UserShareTable(
                sender = self.id,
                name = name,
                salt = key[2],
                value = key[1],
                shareUid = ids[i]
            )
            self.c.add(row)
            self.c.flush()
        self.c.commit()

    @userExistRequired
    def shareGet(self, name:str) -> bytes:
        """Get data set by shareSet

        Arguments:
            name -- The "name of the data"

        Raises:
            ValueError: if decryption fails

        Returns:
            Decrypted data
        """
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
        # Generate new Keys and add old keys to backup
        backups = self.getData("_backupAESKeys")
        self.backupAESKeys:list[bytes] = pickle.loads(backups)
        base.zeromem(backups)
        self.backupAESKeys.append(self._key)

        tag = factors.password.getAuth(pwd)
        stmt = update(DBschemas.UserTable).where(DBschemas.UserTable.name == self.userName).\
            values(pwdAuthToken = tag)
        self.c.execute(stmt)
        self.c.flush()
        self.c.commit()
        self._key = factors.password.auth(tag, pwd)

        backups = pickle.dumps(self.backupAESKeys)
        self.setData("_backupAESKeys", backups)
        base.zeromem(backups)

        keys = base.createECCKey()
        backups = self.getData("_backupKeys")
        self.backupKeys:list[bytes] = pickle.loads(backups)
        base.zeromem(backups)
        self.backupKeys.append(self._privKey)
        backups = pickle.dumps(self.backupKeys)
        self.setData("_backupKeys", backups)
        base.zeromem(backups)
        self._privKey = keys[0]
        self.pubKey = keys[1]
        self.setData("_userPrivateKey", self._privKey)
        self.setData("_userPublicKey", self.pubKey)
        row = DBschemas.PubKeyTable(
            Uid = self.id,
            key = self.pubKey
        )
        self.c.add(row)
        self.c.flush()
        self.c.commit()

        self.setData("_accountKeysCreation", str(datetime.datetime.now().year))
        self.reload()

    @userExistRequired
    def reload(self):
        """Reload encryption keys. Warning: previous keys are not purged!
        """
        _privKey = self.getData("_userPrivateKey")
        pubKey = self.getData("_userPublicKey")
        self._privKey = _privKey.decode()
        self.pubKey = pubKey.decode()
        base.zeromem(_privKey)
        keys = self.getData("_backupAESKeys")
        self.backupAESKeys = pickle.loads(keys)
        base.zeromem(keys)
        keys = self.getData("_backupKeys")
        self.backupKeys = pickle.loads(keys)
        base.zeromem(keys)

    def __del__(self):
        if self.loggedin:
            base.zeromem(self._key)
            base.zeromem(self._privKey)
            base.zeromem(self.backupAESKeys)
            base.zeromem(self.backupKeys)
            self.c.flush()
            self.c.commit()
            self.c.close()
