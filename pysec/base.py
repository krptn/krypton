import ctypes
import sys
import __CryptoLib
from sqlalchemy import select
from . import configs, DBschemas

Adrr = id
#Load FIPS Validated resolver 
__CryptoLib.fipsInit() 

#Wrappers for __CryptoLib to help intelisense automatically figure out function arguments, etc..
def _restEncrypt(data:str|bytes, key:bytes) -> bytes:
    return __CryptoLib.AESEncrypt(data, key, len(data))
def _restDecrypt(data:bytes, key:bytes) -> bytes:
    return __CryptoLib.AESDecrypt(data, key)
def base64encode(data:str|bytes) -> str:
    return __CryptoLib.base64encode(data, len(data))
def base64decode(data:str|bytes) -> bytes|str:
    return __CryptoLib.base64decode(data, len(data))
# returns (privateKey, PubKey)
def createECCKey() -> tuple[bytes, bytes]:
    return __CryptoLib.createECCKey()
def ECDH(privKey:str, peerPubKey:str, salt:bytes, hashNum:int=configs.defaultIterations, keylen:int=32) -> bytes:
    return __CryptoLib.getECCSharedKey(privKey, peerPubKey, salt, hashNum, keylen)
def getSharedKey(privKey:str, peerName:str, salt:bytes, hashNum:int=configs.defaultIterations, keylen:int=32) -> bytes:
    stmt = select(DBschemas.pubKeyTable).where(DBschemas.pubKeyTable.name == peerName)
    key = configs.SQLDefaultUserDBpath.scalar(stmt)["key"]
    return __CryptoLib.getSharedKey(privKey, key, salt, hashNum, keylen)
def PBKDF2(text:str|bytes, salt:str|bytes, iter:int, keylen:int=32) -> bytes:
    return __CryptoLib.PBKDF2(text, len(text), salt, iter, len(salt), keylen)

#C-Style function to clear the content of str and bytes
def zeromem(obj:str)->int:
    return ctypes.memset(id(obj)+(sys.getsizeof(obj)-len(obj)),0,len(obj))
