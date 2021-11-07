#from PySec import Basic
#from PySec import decorators
import hashlib
import sys
import ctypes
import sys

DEBUG = True
if sys.platform == "win32" and DEBUG:
    sys.path.append(r"CryptoLib\out\build\x64-Debug\Debug")
elif sys.platform == "win32" and not DEBUG:
    sys.path.append(r"CryptoLib\out\build\x64-Release\RelWithDebInfo")
elif sys.platform != "win32" and DEBUG:
    sys.path.append(r"CryptoLib\out\build\Linux-Clang-Debug")
else:
    sys.path.append(r"CryptoLib\out\build\Linux-Clang-Release")

version = "1"
from CryptoLib import AESEncrypt, AESDecrypt
def Decrypt(data:bytes,key:bytes):
    return AESDecrypt(data,key)
def Encrypt(data:bytes,key:bytes):
    return AESEncrypt(data,key)
    
__all__ = ["Basic","decorators"]
ignore = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__']
search = 9
def getUser():
    return b"not connected to cloud"
data_path = "Data/"
key = "PySec.key"
key_path = data_path+key

class StrBuilder():
    def __init__(self,lenNum : int):
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

def antiSQLi(name:bytes, info:bool=True)->bytes:
    #Santizes and de-santizes inputs before constructing sql cmds to avoid injections
    if info:
        a = StrBuilder(len(name)*3+3)
        a.StringAdd(b'"')
        for ch in name:
            a.StringAdd((str(ord(ch))+"/").encode("utf-8"))
        result = a.StrValue()[:-1]
        result+=b'"'
        a.Clear()
    elif not info:
        a = StrBuilder(round((len(name)-3)/4))
        a.StringAdd(b'"')
        nameb = name[1:]
        zeromem(name)
        name=nameb[:-1]
        zeromem(nameb)
        t = name.split(b"/")
        for i in t:
            a.StringAdd(chr(int(i)))
        result = a.StrValue
        a.Clear()
    else:
        raise TypeError("Must be type str or type int")
    return result
