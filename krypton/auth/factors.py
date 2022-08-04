"""
Different Auth Factors available inside krypton.
"""
import os
import base64

from .. import base
from .. import configs

KEY_LEN = 32

class authFailed(Exception):
    """
    Exception to be raised when an error occures in a user model.
    """
    def __init__(self, *args: object) -> None:
        self.message = args[0]
        super().__init__()
    def __str__(self) -> str:
        return self.message

class password:
    """
    *Note:* no need to create an object just call the methods directly.
    Simple password authentication.

    1.) Hash the password with PBKDF2 and random salt.

    2.) Decrypt the value in the table arg.

    3.) Verify that the decryption was successfully authenticated.

    4.) Return the encryption key.
    """
    @staticmethod
    def getAuth(pwd:str):
        """Generate authentication tag for later use

        Arguments:
            pwd -- Password

        Returns:
            Auth tag
        """
        salt = os.urandom(12)
        key = base.PBKDF2(pwd, salt, keylen=KEY_LEN)
        text = os.urandom(12)
        authTag = f"{base.base64encode(base.restEncrypt(text, key))}${base.base64encode(salt)}${configs.defaultIterations}"
        return authTag
    
    @staticmethod
    def auth(authTag:str, pwd:str) -> bytes:
        """Authenticate against a tag

        Arguments:
            authTag -- Tag

            pwd -- Password

        Returns:
            Encryption key if success, False otherwise
        """
        splited = authTag.split("$")
        ctext, salt, iter = base.base64decode(splited[0]), base.base64decode(splited[1]), int(splited[2])
        key = base.PBKDF2(pwd, salt, iter, KEY_LEN)
        text = base.restDecrypt(ctext, key) # This raises an error if authentication fails.
        return key ## Success

class totp:
    """
    Simple TOTP authentication
    """

    @staticmethod
    def createTOTP(userName:str):
        """Create parameters for TOTP Generate

        Arguments:
            userName -- The username

        Returns:
            shared secret, base32 encoded shared secret, totp uri
        """
        secret = os.urandom(20)
        base32Secret = base64.b32encode(secret)
        return secret, base32Secret, base.createTOTPString(secret, userName)
    
    @staticmethod
    def verifyTOTP(secret:bytes, otp:str) -> bool:
        """Verify TOTP

        Arguments:
            secret -- The Shared secret
            otp -- The OTP

        Returns:
            True if success False otherwise
        """
        if not base.verifyTOTP(secret, otp):
            return False
        return True

class recoveryCode:
    """
    Restore an account using a recovery code.
    """

class fido:
    """
    FIDO authentication support.
    """
