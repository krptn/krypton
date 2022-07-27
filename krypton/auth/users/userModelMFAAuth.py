""" Extended auth logic
"""
#pylint: disable=W0223
#pylint: disable=no-member
import os
from sqlalchemy import select, delete
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
        """The method name says it all."""

    @userExistRequired
    def disableMFA(self):
        """The method name says it all."""
