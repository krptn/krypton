""" Extended auth logic
"""
#pylint: disable=no-member
#pylint: disable=attribute-defined-outside-init
#pylint: disable=abstract-method
import os
from sqlalchemy import select, delete, update

from krypton.auth import factors
from ... import DBschemas, configs, base
from .bases import userExistRequired, user

class MFAUser(user):
    @userExistRequired
    def enablePWDReset(self) -> list[str]:
        PKeys = [base.genOTP() for i in range(10)]
        self.c.execute(delete(DBschemas.PWDReset).where(DBschemas.PWDReset.Uid == self.id))
        for PKey in PKeys:
            salt = os.urandom(32)
            key = base.PBKDF2(PKey, salt, keylen=32)
            skey = base.restEncrypt(self._key, key)
            base.zeromem(key)
            row = DBschemas.PWDReset(
                Uid = self.id,
                key = skey,
                iter = configs.defaultIterations,
                salt = salt
            )
            self.c.add(row)
            self.c.flush()
        self.c.commit()
        return PKeys

    def resetPWD(self, key:str, newPWD:str):
        rows = self.c.execute(select(DBschemas.PWDReset).where(DBschemas.PWDReset.Uid == self.id)).scalars().all()
        reset = False
        for row in rows:
            krKey = base.PBKDF2(key, row.salt, row.iter, 32)
            try:
                self._key = base.restDecrypt(row.key, krKey)
            except ValueError:
                continue
            base.zeromem(krKey)
            self.loggedin = True
            self.c.execute(delete(DBschemas.PWDReset).where(DBschemas.PWDReset.id == row.id))
            self.generateNewKeys(newPWD)
            self.login(newPWD)
            reset = True
            break
        if not reset:
            raise ValueError("Password reset failure")
        self.c.commit()
    
    @userExistRequired
    def disablePWDReset(self):
        self.c.execute(delete(DBschemas.PWDReset).where(DBschemas.PWDReset.Uid == self.id))
        self.c.commit()

    @userExistRequired
    def enableMFA(self):
        secret, base32Secret, string = factors.totp.createTOTP(self.userName)
        stmt = update(DBschemas.UserTable).where(DBschemas.UserTable.name == self.userName).\
            values(mfa = base.restEncrypt(secret, self._key))
        self.c.execute(stmt)
        self.c.flush()
        self.c.commit()
        base.zeromem(secret)
        return base32Secret, string

    @userExistRequired
    def disableMFA(self):
        """The method name says it all."""
        stmt = update(DBschemas.UserTable).where(DBschemas.UserTable.name == self.userName).\
            values(mfa = b"*")
        self.c.execute(stmt)
