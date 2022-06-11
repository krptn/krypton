"""
Loads CryptoLib and creates wrappers for cryptographic modules
"""

import ctypes
import sys
from sqlalchemy import select
import __CryptoLib
from . import configs, DBschemas
from typing import ByteString

Adrr = id
#Load FIPS Validated resolver
__CryptoLib.fipsInit()

#Wrappers for __CryptoLib to help intelisense automatically figure out function arguments, etc..
def _restEncrypt(data:ByteString, key:bytes) -> bytes:
    """Wrappers for __CryptoLib
    To help intelisense automatically figure out function arguments, etc.."""
    return __CryptoLib.AESEncrypt(data, key, len(data))
def _restDecrypt(data:bytes, key:bytes) -> bytes:
    """Wrappers for __CryptoLib
    To help intelisense automatically figure out function arguments, etc.."""
    return __CryptoLib.AESDecrypt(data, key)
def base64encode(data:ByteString) -> str:
    """Wrappers for __CryptoLib
    To help intelisense automatically figure out function arguments, etc.."""
    return __CryptoLib.base64encode(data, len(data))
def base64decode(data:ByteString) -> ByteString:
    """Wrappers for __CryptoLib
    To help intelisense automatically figure out function arguments, etc.."""
    return __CryptoLib.base64decode(data, len(data))
# returns (privateKey, PubKey)
def createECCKey() -> tuple[bytes, bytes]:
    """Wrappers for __CryptoLib
    To help intelisense automatically figure out function arguments, etc.."""
    return __CryptoLib.createECCKey()
def ECDH(privKey:str, peerPubKey:str, salt:bytes, hashNum:int=configs.defaultIterations, keylen:int=32) -> bytes:
    """Wrappers for __CryptoLib
    To help intelisense automatically figure out function arguments, etc.."""
    return __CryptoLib.getECCSharedKey(privKey, peerPubKey, salt, hashNum, keylen)
def getSharedKey(privKey:str, peerName:str, salt:bytes, hashNum:int=configs.defaultIterations, keylen:int=32) -> bytes:
    """Wrappers for __CryptoLib
    To help intelisense automatically figure out function arguments, etc.."""
    stmt = select(DBschemas.PubKeyTable).where(DBschemas.PubKeyTable.name == peerName)
    key = configs.SQLDefaultUserDBpath.scalar(stmt)["key"]
    return __CryptoLib.getSharedKey(privKey, key, salt, hashNum, keylen)
def PBKDF2(text:ByteString, salt:ByteString, iterations:int, keylen:int=32) -> bytes:
    """Wrappers for __CryptoLib
    To help intelisense automatically figure out function arguments, etc.."""
    return __CryptoLib.PBKDF2(text, len(text), salt, iterations, len(salt), keylen)

def zeromem(obj:str)->int:
    """C-Style function to clear the content of str and bytes"""
    return ctypes.memset(id(obj)+(sys.getsizeof(obj)-len(obj)),0,len(obj))
