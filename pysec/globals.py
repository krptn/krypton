import ctypes
import sqlite3
import sys
from . import __userDB
__userC:sqlite3.Cursor = __userDB.cursor()
Adrr = id
import __CryptoLib
__CryptoLib.fipsInit() #Load FIPS Validated resolver 

#Wrappers for __CryptoLib to help intelisense automatically figure out function arguments, etc..
def _restEncrypt(data:str|bytes, key:bytes) -> bytes:
    return __CryptoLib.AESEncrypt(data, key)
def _restDecrypt(data:bytes, key:bytes) -> bytes:
    return __CryptoLib.AESDecrypt(data, bytes)
def _getKey(pwd:str|bytes) -> bytes:
    return __CryptoLib.getKeyFromPass(pwd)
def base64encode(data:str|bytes, len:int) -> str:
    return __CryptoLib.base64encode(data, len)
def base64decode(data:str|bytes, len:int) -> bytes|str:
    return __CryptoLib.base64decode(data, len)
def createECCKey() -> tuple[bytes, bytes]: # returns (publicKey, privateKey)
    return __CryptoLib.createECCKey()
def ECDH(privKey:bytes, peerPubKey:bytes) -> bytes:
    return __CryptoLib.getECCSharedKey(privKey, peerPubKey)
def getSharedKey(privKey:bytes, peerName:str) -> bytes:
    key = __userC.execute("SELECT key FROM pubKeys WHERE name=?", (peerName,)).fetchone()
    __CryptoLib.getECCSharedKey(privKey, key)

def zeromem(obj:str)->None: #C-Style function to clear the content of str and bytes
    ctypes.memset(id(obj)+(sys.getsizeof(obj)-len(obj)),0,len(obj))
