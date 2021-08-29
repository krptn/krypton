﻿#from PySec import Basic
#from PySec import decorators
import hashlib
import sys
import ctypes
#import PySec
DEBUG = True
if sys.platform == "win32" and DEBUG:
    a = ctypes.cdll.LoadLibrary(r"CryptoLib\out\build\x64-Debug\Debug/CryptoLib.dll")
elif sys.platform == "win32" and not DEBUG:
    a = ctypes.cdll.LoadLibrary(r"CryptoLib\out\build\x64-Release\RelWithDebInfo/CryptoLib.dll")
elif sys.platform != "win32" and DEBUG:
    a = ctypes.cdll.LoadLibrary(r"CryptoLib\out\build\Linux-Clang-Debug\CryptoLib.so")
else:
    a = ctypes.cdll.LoadLibrary(r"CryptoLib\out\build\Linux-Clang-Release\CryptoLib.so")

class ret(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_ubyte)),
        ("len", ctypes.c_int),
        ("str", ctypes.c_bool)]

Encrypt = a.NonNativeAESEncrypt
Encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
Encrypt.restype = ret
strbuff = ctypes.create_string_buffer
NewStrBuilder = ctypes.create_string_buffer

def RestEncrypt(ctext : bytes, key : bytes) -> bytes:
    re = Encrypt(ctext, key)
    s = re.data[0:re.len]
    #s = ctypes.cast(re.data, ctypes.c_char_p).raw[:re.len]
    print("Cipher text ",s)
    return s

Decrypt = a.NonNativeAESDecrypt
Decrypt.argtypes = [ret, ctypes.c_char_p]
Decrypt.restype = ctypes.c_char_p

def RestDecrypt(ctext : bytes, key : bytes) -> bytes:
    text = ret()
    text.len=len(ctext)
    text.data=ctypes.cast((ctypes.c_ubyte * text.len)(*ctext) ,ctypes.POINTER(ctypes.c_ubyte))
    text.str=True
    re = Decrypt(text,key)
    return re

__all__ = ["Basic","decorators"]
ignore = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__']
search = 9
def getUser():
    return b"not connected to cloud"

key = "PySec.key"
DEBUG = True

StrAdd = a.AddToStrBuilder
StrAdd.argtypes = [ctypes.c_char_p,ctypes.c_char_p,ctypes.c_int]
StrAdd.restype = ctypes.c_int
class StrBuilder():
    def __init__(self,lenNum : int):
        self.len = lenNum +1
        self.data = ctypes.create_string_buffer(lenNum)
    def StringAdd(self, data : bytes, lenNum : int) -> None:
        if self.len <= (len(data)+lenNum):
            StrAdd(self.data,data,lenNum)
        else:
            raise ValueError("Data is longer than buffer size.")
    StrValue = lambda self: self.data.value
    def Clear(self) -> None:
        ctypes.memset(self.data,0,self.len)
    def __del__(self):
        self.Clear()
