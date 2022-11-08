""" This module contains auth functions for models
"""
#pylint: disable=no-member
#pylint: disable=attribute-defined-outside-init
#pylint: disable=abstract-method
import datetime
import os
import pickle
from sqlalchemy import delete, select, func, update
from .. import factors, _utils
from ... import DBschemas, configs
from ... import base
from .bases import userExistRequired, UserError, user

class AuthUser(user):
    """Auth Logic for User Models
    """
    def login(self, pwd:str, mfaToken:str="", fido:str=None):
        """Log the user in

        Keyword Arguments:
            pwd -- Password

            otp -- One-Time Password (default: {""})

            fido -- Fido Credentials (default: {None})

        Raises:
            UserError: Password is not set or wrong password is provided.

        Returns:
            Session Key
        """
        if not self.saved:
            raise UserError("User must be saved.")
        stmt = select(DBschemas.UserTable).where(DBschemas.UserTable.id == self.id).limit(1)
        authTag:DBschemas.UserTable = self.c.scalar(stmt)
        if authTag.fidoID != b"*":
            if fido is None or factors.fido.authenticate_verify(authTag.fidoChallenge, authTag.fidoPub, fido) is False:
                self.FIDORequired = True
                raise UserError("Failed to verify FIDO credentials.")
        if authTag.pwdAuthToken is None:
            raise UserError("User must have a password set.")
        self._key = factors.password.auth(authTag.pwdAuthToken, pwd)
        if self._key is False: raise UserError("Wrong password")
        if authTag.mfa != b"*":
            mfa = base.restDecrypt(authTag.mfa, self._key)
            if not factors.totp.verifyTOTP(mfa, mfaToken):
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
        self.c.flush()
        self.loggedin = True
        time = int(self.getData("_accountKeysCreation").decode())
        if (datetime.datetime.now().year - time) >= 2:
            self.generateNewKeys(pwd)
        self.reload()
        self.c.flush()
        self.c.commit()
        encoded = base.base64encode(restoreKey)
        base.zeromem(restoreKey)
        return encoded

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

    @userExistRequired
    def delete(self):
        """Delete a user
        """
        _utils.cleanUpSessions(self.c, self.id)
        self.c.execute(delete(DBschemas.UserTable).where(DBschemas.UserTable.id == self.id))
        self.c.execute(delete(DBschemas.PubKeyTable).where(DBschemas.PubKeyTable.Uid == self.id))
        self.c.execute(delete(DBschemas.UserData).where(DBschemas.UserData.Uid == self.id))
        self.c.execute(delete(DBschemas.UserShareTable).where(DBschemas.UserShareTable.sender == self.userName))
        self.c.execute(delete(DBschemas.PWDReset).where(DBschemas.PWDReset.Uid == self.id))
        self.c.flush()
        self.c.commit()
        base.zeromem(self._key)
        base.zeromem(self._privKey)

    def restoreSession(self, key):
        """Resume sessoin from key

        Arguments:
            key -- Session Key
        """
        if key is None:
            raise UserError("Session does not exist or is expired.")
        _utils.cleanUpSessions(session=self.c)
        decodedKey = base.base64decode(key)
        stmt = select(DBschemas.SessionKeys).where(DBschemas.SessionKeys.Uid == self.id)
        rows:list[DBschemas.SessionKeys] = self.c.scalars(stmt)
        success = False
        for row in rows:
            if row is None:
                raise UserError("Session does not exist or is expired.")
            try:
                self._key = base.restDecrypt(row.key, decodedKey)
                self.sessionKey = row.key
            except ValueError:
                pass
            else:
                success = True
        if not success:
            raise UserError("Session does not exist or is expired.")
        self.loggedin = True
        self.reload()

    def saveNewUser(self, name:str, pwd:str) -> bytes:
        """Save a new user

        Arguments:
            name -- User Name

            pwd -- Password

        Raises:
            ValueError: If user is already saved
        """
        if self.saved:
            raise ValueError("This user is already saved.")
        s = self.c.scalar(select(DBschemas.UserTable).where(DBschemas.UserTable.name == name))
        if s is not None:
            raise ValueError("This user is already exists.")
        self.userName = name
        stmt = select(func.max(DBschemas.UserTable.id))
        self.id = self.c.scalar(stmt) + 1
        keys = base.createECCKey()
        self._privKey = keys[0]
        self.pubKey = keys[1]
        key = DBschemas.PubKeyTable(
            Uid = self.id,
            key = self.pubKey
        )
        self.c.add(key)
        self.c.flush()
        tag = factors.password.getAuth(pwd)
        userEntry = DBschemas.UserTable(
            id = self.id,
            name = name,
            pwdAuthToken = tag
        )
        self.c.add(userEntry)
        self.c.flush()
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

    def revokeSessions(self):
        """Revoke all Sessions for this User

        Raises:
            UserError: If the user does not exist
        """
        if not self.saved:
            raise UserError("This user does not exist.")
        _utils.cleanUpSessions(self.c, self.id)

    @userExistRequired
    def changeUserName(self, newUserName:str):
        stmt = update(DBschemas.UserTable).where(DBschemas.UserTable.id == self.id).\
            values(name = newUserName)
        self.c.execute(stmt)
        self.c.flush()
        self.c.commit()
        self.userName = newUserName
