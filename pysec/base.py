import ctypes
import sqlite3
import sys
from . import configs
__userC:sqlite3.Cursor = configs.SQLDefaultUserDBpath.cursor()
Adrr = id
import __CryptoLib
__CryptoLib.fipsInit() #Load FIPS Validated resolver 

#Wrappers for __CryptoLib to help intelisense automatically figure out function arguments, etc..
def _restEncrypt(data:str|bytes, key:bytes) -> bytes:
    return __CryptoLib.AESEncrypt(data, key, len(data))
def _restDecrypt(data:bytes, key:bytes) -> bytes:
    return __CryptoLib.AESDecrypt(data, key)
def base64encode(data:str|bytes) -> str:
    return __CryptoLib.base64encode(data, len(data))
def base64decode(data:str|bytes) -> bytes|str:
    return __CryptoLib.base64decode(data, len(data))
def createECCKey() -> tuple[bytes, bytes]: # returns (publicKey, privateKey)
    return __CryptoLib.createECCKey()
def ECDH(privKey:str, peerPubKey:str, salt:bytes) -> bytes:
    return __CryptoLib.getECCSharedKey(privKey, peerPubKey, salt, 100000)
def getSharedKey(privKey:str, peerName:str, salt:bytes) -> bytes:
    key = __userC.execute("SELECT key FROM pubKeys WHERE name=?", (peerName,)).fetchone()
    __CryptoLib.getSharedKey(privKey, key, salt, 100000)
def PBKDF2(text:str|bytes, salt:str|bytes, iter:int) -> bytes:
    return __CryptoLib.PBKDF2(text, salt, iter, len(salt))

def zeromem(obj:str)->None: #C-Style function to clear the content of str and bytes
    ctypes.memset(id(obj)+(sys.getsizeof(obj)-len(obj)),0,len(obj))
