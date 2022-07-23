"""
Loads __CryptoLib and contains wrappers.
"""

import ctypes
import sys
from typing import ByteString
from sqlalchemy import select
import __CryptoLib
from . import configs, DBschemas

Adrr = id

#: Load FIPS Validated resolver
__CryptoLib.fipsInit()

#: Wrappers for __CryptoLib #
# : Help linters automatically figure out function arguments, returns, etc..
def restEncrypt(data:ByteString, key:bytes) -> bytes:
    """Encrypt Data for at rest Storage

    Arguments:
        data -- Plaintext

        key -- 32-bit key

    Returns:
        Ciphertext
    """
    return __CryptoLib.AESEncrypt(data, key, len(data))

def restDecrypt(data:bytes, key:bytes) -> bytes:
    """Decrypt Data from restEncrypt

    Arguments:
        data -- Ciphertext

        key -- 32-bit key

    Returns:
        Plaintext
    """
    return __CryptoLib.AESDecrypt(data, key)

def base64encode(data:ByteString) -> str:
    """Base64 Encoding

    Arguments:
        data -- Text to encode

    Returns:
        Base64 encoded string
    """
    return __CryptoLib.base64encode(data, len(data))

def base64decode(data:ByteString) -> ByteString:
    """Decode base64

    Arguments:
        data -- Base64 encoded string

    Returns:
        Base64 decoded bytes
    """
    return __CryptoLib.base64decode(data, len(data))

def createECCKey() -> tuple[str, str]:
    """create an ECC Key

    Encoded in PEM format

    Returns:
        Returns a tuple like (privateKey:str, publicKey:str)
    """
    return __CryptoLib.createECCKey()

def ECDH(privKey:str, peerPubKey:str, salt:bytes, keylen:int=32) -> bytes:
    """Elliptic Curve Diffie-Helman

    Arguments:
        privKey -- PEM Encoded private key

        peerPubKey -- PEM Encoded public key

        salt -- Salt used for KDF

    Keyword Arguments:
        keylen -- Len of the key (default: {32})

    Returns:
        Key as python bytes
    """
    return __CryptoLib.ECDH(privKey, peerPubKey, salt, keylen)

def getSharedKey(privKey:str, peerName:str, salt:bytes, keylen:int=32) -> bytes:
    """Get users' shared key

    Get a shared key for two users using ECDH.

    Arguments:
        privKey -- User's private EC Key (in PEM format)

        peerName -- Other User's user name

        salt -- Salt used for KDF

    Keyword Arguments:
        keylen -- Len of kex to return (default: {32})

    Returns:
        Key as python bytes
    """
    stmt = select(DBschemas.PubKeyTable.key).where(DBschemas.PubKeyTable.name == peerName)
    key = configs.SQLDefaultUserDBpath.scalar(stmt)
    return __CryptoLib.ECDH(privKey, key, salt, keylen)

def PBKDF2(text:ByteString, salt:ByteString, iterations:int=configs.defaultIterations, keylen:int=32) -> bytes:
    """PBKDF2 with SHA512

    Arguments:
        text -- Plaintext
        salt -- Salt

    Keyword Arguments:
        iterations -- Iteration count (default: {configs.defaultIterations})

        keylen -- Len of key to return (default: {32})

    Returns:
        The key as python bytes
    """
    return __CryptoLib.PBKDF2(text, len(text), salt, iterations, len(salt), keylen)

def zeromem(obj:ByteString)->int:
    """Set the byte/string to \x00

    WARNING! Improper use leads to severe memory corruption.
    Ensure you only use it with bytes and string objects.
    IT HAS NO ERROR OR TYPE CHECKS!

    Arguments:
        obj -- Object to do this on (bytes and str are supported!)

    Returns:
        Result from memset.
    """
    return ctypes.memset(id(obj)+(sys.getsizeof(obj)-len(obj)),0,len(obj))
