"""
Loads __CryptoLib and contains wrappers.
"""
# pylint: disable=import-error
# disbaled pylint because __CryptoLib is not built in CI/CD tests

import ctypes
import hmac
import sys
import base64
import os
import datetime
import hashlib
from typing import ByteString

try:
    import __CryptoLib
except ImportError as err:
    if sys.platform == "win32" and not os.path.isfile(
        "C:/Windows/System32/MSVCP140.dll"
    ):
        raise RuntimeError(
            "This module requires Microsoft Visual C/C++ runtime. "
            "Please download it from https://learn.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist."
        ) from err
    raise err
from . import configs

Adrr = id

TOTP_SECRET_LEN = configs._totpSecretLen
TOTP_CODE_LEN = 6

__CryptoLib.init()


#: Wrappers for __CryptoLib
#: Help static analyzers automatically figure out function arguments, returns, etc..
def seal(data: ByteString, key: bytes) -> bytes:
    """Encrypt Data for at rest storage

    Arguments:
        data -- Plain text

        key -- 32-byte key

    Returns:
        Cipher text
    """
    return __CryptoLib.encrypt(data, key)


def unSeal(data: bytes, key: bytes) -> bytes:
    """Decrypt Data from restEncrypt

    Arguments:
        data -- Cipher text

        key -- 32-byte key

    Returns:
        Plain text
    """
    return __CryptoLib.decrypt(data, key)


def base64encode(data: ByteString) -> str:
    """Base64 Encoding

    Arguments:
        data -- Text to encode

    Returns:
        Base64 encoded string
    """
    return __CryptoLib.base64encode(data)


def base64decode(data: ByteString) -> ByteString:
    """Decode base64

    Arguments:
        data -- Base64 encoded string

    Returns:
        Base64 decoded bytes
    """
    return __CryptoLib.base64decode(data)


def createECCKey() -> tuple[str, str]:
    """create an Eliptic Curve Key

    Encoded in P.E.M. format

    Returns:
        Returns a tuple like (privateKey:str, publicKey:str)
    """
    return __CryptoLib.createECCKey()


def encryptEcc(privKey: bytes, pubKey: bytes, data: ByteString) -> bytes:
    """Encrypt data using public/private keys

    Args:
        privKey (bytes): Private Key
        pubKey (bytes): Public Key
        data (ByteString): Data to encrypt

    Returns:
        bytes: the encrypted data
    """
    return __CryptoLib.encryptEcc(privKey, pubKey, data)


def decryptEcc(privKey: bytes, pubKey: bytes, data: ByteString) -> bytes:
    """Decrypt data using public/private keys

    Args:
        privKey (bytes): Private Key
        pubKey (bytes): Public Key
        data (ByteString): Data to decrypt

    Returns:
        bytes: the decrypted data
    """
    return __CryptoLib.decryptEcc(privKey, pubKey, data)


def passwordHash(
    text: ByteString,
    salt: ByteString,
    opsLimit: int = configs.defaultArgonOps,
    keylen: int = configs._aesKeyLen,
) -> bytes:
    """Argon2id

    Arguments:
        text -- Plain text
        salt -- Salt

    Keyword Arguments:
        keylen -- Len of key to return (default: {32})
        opsLimit -- Ops Limit for Argon2id

    Returns:
        The key as python bytes
    """
    return __CryptoLib.passwordHash(
        text, salt, opsLimit, configs._memLimitArgon, keylen
    )


def zeromem(obj: ByteString) -> int:
    """Set the byte/string to \\x00

    WARNING! Improper use leads to severe memory corruption.
    Ensure you only use it with bytes and string objects.
    Also, on PyPy this function does nothing to avoid corruption.

    Arguments:
        obj -- Object to do this on (bytes and str are supported!)

    Returns:
        Result from memset.
    """
    assert isinstance(obj, str) or isinstance(obj, bytes)
    if "PyPy" not in sys.version:
        return ctypes.memset(id(obj) + (sys.getsizeof(obj) - len(obj)), 0, len(obj))
    return None


def verifyTOTP(secret: bytes, code: str) -> bool:
    """Verify a 6-digit TOTP

    Arguments:
        secret -- The shared secret

        code -- The code to verify

    Returns:
        True is success False otherwise
    """
    if len(secret) != TOTP_SECRET_LEN or len(code) != TOTP_CODE_LEN:
        raise ValueError("Incorrect secret or code len in verifyTOTP")
    counter = datetime.datetime.now().timestamp() / 30
    byteCounter = int(counter).to_bytes(8, "big")
    md = hmac.digest(secret, byteCounter, hashlib.sha1)
    offset = md[19] & 0x0F
    bin_code = (
        (md[offset] & 0x7F) << 24
        | (md[offset + 1] & 0xFF) << 16
        | (md[offset + 2] & 0xFF) << 8
        | (md[offset + 3] & 0xFF)
    )
    bin_code = bin_code % 1000000
    if (
        __CryptoLib.compHash(
            format(bin_code, f"0{TOTP_CODE_LEN}d"), code, TOTP_CODE_LEN
        )
        == 0
    ):
        return True
    sleepOutOfGIL(5)
    return False


def createTOTPString(secret: bytes, user: str) -> str:
    """Create a TOTP String that can be scanned by Auth Apps

    Arguments:
        secret -- The shared secret

    Returns:
        The String to be converted to QR code
    """
    assert isinstance(user, str)
    s = base64.b32encode(secret)
    secret = s.decode()  # This is not base64 decoding. It is bytes -> string decoding.
    stripped = secret.strip("=")
    string = f"otpauth://totp/{configs.APP_NAME}:{user}?secret={stripped}&issuer=KryptonAuth&algorithm=SHA1&digits={TOTP_CODE_LEN}&period=30"
    zeromem(s)
    zeromem(secret)
    zeromem(stripped)
    return string


def genOTP() -> str:
    """Generate an 12-digit OTP/PIN.

    Returns:
        The OTP/PIN as python string
    """
    return __CryptoLib.genOTP()


def sleepOutOfGIL(seconds: int = 5) -> bool:
    """Sleep for seconds while releasing the GIL.

    Keyword Arguments:
        seconds -- Number of seconds to sleep for (default: {5})

    Returns:
        True
    """
    return __CryptoLib.sleepOutOfGIL(seconds)
