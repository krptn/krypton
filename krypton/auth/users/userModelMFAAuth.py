""" Extended auth logic
"""
#pylint: disable=W0223
#pylint: disable=no-member
import base64
import os
from sqlalchemy import select, delete, update
from ... import DBschemas, configs, base
from .bases import userExistRequired, user

class MFAUser(user):
    @userExistRequired
    def enablePWDReset(self, Pkey):
        salt = os.urandom(32)
        key = base.PBKDF2(Pkey, salt, keylen=32)
        skey = base.restEncrypt(self._key, key)
        base.zeromem(key)
        self.c.execute(delete(DBschemas.PWDReset).where(DBschemas.PWDReset.Uid == self.id))
        row = DBschemas.PWDReset(
            Uid = self.id,
            key = skey,
            iter = configs.defaultIterations,
            salt = salt
        )
        self.c.add(row)
        self.c.commit()

    def resetPWD(self, key:str, newPWD:str):
        row:DBschemas.PWDReset = self.c.scalar(select(DBschemas.PWDReset).where(DBschemas.PWDReset.Uid == self.id))
        krKey = base.PBKDF2(key, row.salt, row.iter, 32)
        self._key = base.restDecrypt(row.key, krKey)
        base.zeromem(krKey)
        self.loggedin = True
        self.generateNewKeys(newPWD)
        self.login(newPWD)

    @userExistRequired
    def enableMFA(self):
        secret = os.urandom(20)
        stmt = update(DBschemas.UserTable).where(DBschemas.UserTable.name == self.userName).\
            values(mfa = base.restEncrypt(secret, self._key))
        self.c.execute(stmt)
        base32Secret = base64.b32encode(secret)
        base.zeromem(secret)
        secret = base32Secret.decode()
        base.zeromem(base32Secret)
        return secret, base.createTOTPString(secret, self.userName)

    @userExistRequired
    def disableMFA(self):
        """The method name says it all."""
        stmt = update(DBschemas.UserTable).where(DBschemas.UserTable.name == self.userName).\
            values(mfa = b"*")
        self.c.execute(stmt)
