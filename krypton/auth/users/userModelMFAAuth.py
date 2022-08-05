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
        """Enable PWD Reset

        Returns:
            The recovery codes that unlock the account
        """
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
        """Reset a PWD using a recovery code

        Arguments:
            key -- The recovery code
            newPWD -- The new PWD

        Raises:
            ValueError: if the reset fails
        """
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
        """Disbale PWD and revoke all codes
        """
        self.c.execute(delete(DBschemas.PWDReset).where(DBschemas.PWDReset.Uid == self.id))
        self.c.commit()

    @userExistRequired
    def enableMFA(self):
        """Enable TOTP MFA

        Returns:
            base32 encoded shared secret, QR code string
        """
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
        """Disable TOTP based MFA
        """
        stmt = update(DBschemas.UserTable).where(DBschemas.UserTable.name == self.userName).\
            values(mfa = b"*")
        self.c.execute(stmt)
        self.c.commit()

    @userExistRequired
    def beginFIDOSetup(self):
        """Being FIDO Registration
        """
        options, challenge = factors.fido.register(self.id, self.userName)
        self.setData("_tempFIDORegisterChallenge", challenge)
        return options

    @userExistRequired
    def completeFIDOSetup(self, response):
        """Finish FIDO Setup

        Arguments:
            repsonse -- The response from the client
        """
        challenge = self.getData("_tempFIDORegisterChallenge")
        self.deleteData("_tempFIDORegisterChallenge")
        credID, credKey = factors.fido.register_verification(response, challenge)
        self.c.execute(update(DBschemas.UserTable).where(DBschemas.UserTable.name == self.userName).\
            update(fidoPub=credKey, fidoID=credID))
        self.c.commit()
