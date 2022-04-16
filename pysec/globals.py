import ctypes
import sys

Adrr = id
import __CryptoLib
__CryptoLib.fipsInit()

_restEncrypt = __CryptoLib.AESEncrypt
_restDecrypt = __CryptoLib.AESDecrypt

def getEncryptor():
    return _restEncrypt

def getDecryptor():
    return _restDecrypt

class StrBuilder():
    def __init__(self, lenNum : int):
        self.len = lenNum
        self.used = 0
        self.data = ctypes.create_string_buffer(lenNum)
    def StringAdd(self, data : bytes, lenNum:int=-1) -> None:
        if lenNum == -1:
            lenNum = self.used
        if self.len >= (len(data)+lenNum):
            a = bytearray(data)
            self.data[lenNum:len(data)] = a
            self.used+=lenNum
            zeromem(a)
        else:
            raise ValueError("Data is longer than buffer size.")
    StrValue = lambda self: self.data.value
    def Clear(self) -> None:
        ctypes.memset(self.data,0,self.len)
    def __del__(self):
        self.Clear()

def zeromem(obj:str)->None: #C-Style function to clear the content of str and bytes
    ctypes.memset(id(obj)+(sys.getsizeof(obj)-len(obj)),0,len(obj))

def antiSQLi(name:bytes, info:bool=True)->str:
    #Santizes and de-santizes inputs before constructing sql cmds to avoid injections
    if info:
        a = StrBuilder(len(name)*4+3)
        a.StringAdd(b'"')
        for ch in name:
            a.StringAdd((str(ord(ch))+"/").encode("utf-8"))
        result = a.StrValue()[:-1].decode("utf-8")
        result+='"'
        a.Clear()
    elif not info:
        a = StrBuilder(len(name))
        a.StringAdd(b'"')
        nameb = name[1:]
        zeromem(name)
        name=nameb[:-1]
        zeromem(nameb)
        t = name.split(b"/")
        for i in t:
            a.StringAdd(chr(int(i)))
        result = a.StrValue.decode("utf-8")
        a.Clear()
    else:
        raise TypeError("Must be type str or type int")
    return result
