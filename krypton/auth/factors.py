"""
Different Auth Factors available inside krypton.
"""
import os

from .. import base
from .. import configs

KCV = b"kryptonAuth"
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
    Note: no need to create an object just call the methods directly.
    Simple password authentication.
    1.) Hash the password with PBKDF2 and random salt.
    2.) Decrypt the value in the table arg.
    3.) Verify that the decryption was successfully authenticated.
    4.) Return the encryption key.
    """
    @staticmethod
    def getAuth(pwd:str):
        """getAuth generate authentication tag for alter use

        Arguments:
            pwd -- Password

        Returns:
            Auth tag
        """
        salt = os.urandom(12)
        key = base.PBKDF2(pwd, salt, keylen=KEY_LEN)
        text = KCV + os.urandom(32)
        authTag = f"{base.base64encode(base.restEncrypt(text, key))}${base.base64encode(salt)}${configs.defaultIterations}"
        return authTag
    @staticmethod
    def auth(authTag:str, pwd:str) -> bytes:
        """auth Authenticate against a tag

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
        if text.startswith(KCV):
            return key ## Success
        else:
            return False

class otp:
    """
    Simple OTP authentication
    """

class recoveryCode:
    """
    Restore an account using a recovery code.
    """

class fido:
    """
    FIDO authentication support.
    """
