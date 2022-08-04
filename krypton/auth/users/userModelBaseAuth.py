""" This module contains auth functions for models
"""
#pylint: disable=W0223
#pylint: disable=no-member
import datetime
import os
import pickle
from sqlalchemy import delete, select, func
from .. import factors, _utils
from ... import DBschemas, configs
from ... import base
from .bases import userExistRequired, UserError, user

class AuthUser(user):
    """Auth Logic for User Models
    """
    def login(self, pwd:str=None, mfaToken:str="", fido:str=None):
        """Log the user in

        Keyword Arguments:
            pwd -- Password (default: {None})

            otp -- One-Time Password (default: {""})

            fido -- Fido Token (default: {None})

        Raises:
            UserError: Password is not set

        Returns:
            Session Key, None if user is not saved
        """
        if not self.saved:
            raise UserError("User must be saved.")
        stmt = select(DBschemas.UserTable.pwdAuthToken).where(DBschemas.UserTable.id == self.id).limit(1)
        authTag = self.c.scalar(stmt)
        if authTag is None:
            raise UserError("User must have a password set.")
        self._key = factors.password.auth(authTag, pwd)
        if self._key is False: raise UserError("Wrong password")
        stmt = select(DBschemas.UserTable.mfa).where(DBschemas.UserTable.id == self.id).limit(1)
        mfa = self.c.scalar(stmt)
        if mfa != b"*":
            mfa = base.restDecrypt(mfa, self._key)
            if not base.verifyTOTP(mfa, mfaToken):
                base.zeromem(self._key)
                raise UserError("Wrong MFA Token")
        restoreKey = os.urandom(32)
        self.sessionKey = base.restEncrypt(self._key, restoreKey)
        token = DBschemas.SessionKeys(
            Uid = self.id,
            key = self.sessionKey,
            iss = datetime.datetime.now(),
            exp = datetime.datetime.now() + datetime.timedelta(minutes=configs.defaultSessionPeriod)
        )
        self.c.add(token)
        self.loggedin = True
        time = int(self.getData("_accountKeysCreation").decode())
        if (datetime.datetime.now().year - time) >= 2:
            self.generateNewKeys(pwd)
        self.reload()
        self.c.flush()
        self.c.commit()
        return restoreKey

    @userExistRequired
    def logout(self):
        """logout Logout the user and delete the current Session
        """
        base.zeromem(self._key)
        base.zeromem(self._privKey)
        stmt = delete(DBschemas.SessionKeys).where(DBschemas.SessionKeys.key == self.sessionKey)
        self.c.execute(stmt)
        self.c.flush()
        self.c.commit()
        self.loggedin = False
        return

    @userExistRequired
    def delete(self):
        """Delete a user

        Returns:
            None
        """
        _utils.cleanUpSessions(self.c, self.id)
        self.c.execute(delete(DBschemas.UserTable).where(DBschemas.UserTable.id == self.id))
        self.c.execute(delete(DBschemas.PubKeyTable).where(DBschemas.PubKeyTable.name == self.userName))
        self.c.execute(delete(DBschemas.UserData).where(DBschemas.UserData.Uid == self.id))
        self.c.execute(delete(DBschemas.UserShareTable).where(DBschemas.UserShareTable.sender == self.userName))
        self.c.execute(delete(DBschemas.PWDReset).where(DBschemas.PWDReset.Uid == self.id))
        self.c.flush()
        self.c.commit()
        base.zeromem(self._key)
        base.zeromem(self._privKey)
        return None

    def restoreSession(self, key):
        """Resume sessoin from key

        Arguments:
            key -- Session Key
        """
        _utils.cleanUpSessions(session=self.c)
        self.sessionKey = key
        stmt = select(DBschemas.SessionKeys).where(DBschemas.SessionKeys.Uid == self.id).limit(1)
        row:DBschemas.SessionKeys = self.c.scalar(stmt)
        if row is None:
            raise UserError("This session key has expired.")
        self._key = base.restDecrypt(row.key, key)
        self.loggedin = True
        self.reload()

    def saveNewUser(self, name:str, pwd:str, fido:str=None) -> bytes:
        """Save a new user

        Arguments:
            name -- User Name

            pwd -- Password

        Keyword Arguments:
            fido -- Fido Token (default: {None})

        Raises:
            ValueError: If user is already saved
        """
        if self.saved:
            raise ValueError("This user is already saved.")
        s = self.c.scalar(select(DBschemas.UserTable).where(DBschemas.UserTable.name == name))
        if s is not None:
            raise ValueError("This user is already exists.")
        self.userName = name
        self.salt = os.urandom(12)
        stmt = select(func.max(DBschemas.UserTable.id))
        self.id = self.c.scalar(stmt) + 1
        keys = base.createECCKey()
        self._privKey = keys[0]
        self.pubKey = keys[1]
        key = DBschemas.PubKeyTable(
            name = self.userName,
            key = self.pubKey
        )
        self.c.add(key)
        tag = factors.password.getAuth(pwd)
        userEntry = DBschemas.UserTable(
            id = self.id,
            name = name,
            pwdAuthToken = tag,
            salt = self.salt
        )
        self.c.add(userEntry)
        self._key = factors.password.auth(tag, pwd)
        self.saved = True
        self.loggedin = True
        self.setData("_userPrivateKey", self._privKey)
        self.setData("_userPublicKey", self.pubKey)
        self.setData("_backupKeys", pickle.dumps([]))
        self.setData("_backupAESKeys", pickle.dumps([]))
        self.setData("_accountKeysCreation", str(datetime.datetime.now().year))
        self.c.flush()
        self.c.commit()
        return self.login(pwd=pwd)
