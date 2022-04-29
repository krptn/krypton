import ctypes
import sys

Adrr = id
import __CryptoLib
__CryptoLib.fipsInit()

_restEncrypt = __CryptoLib.AESEncrypt
_restDecrypt = __CryptoLib.AESDecrypt
_getKey = __CryptoLib.getKeyFromPass

def getEncryptor():
    return _restEncrypt

def getDecryptor():
    return _restDecrypt

def getECCPubPrivKey():
    pass

def ECCEncrypt():
    pass

def ECCDecrypt():
    pass

def zeromem(obj:str)->None: #C-Style function to clear the content of str and bytes
    ctypes.memset(id(obj)+(sys.getsizeof(obj)-len(obj)),0,len(obj))
