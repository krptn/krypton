import sys
import ctypes
import os
from ctypes import cdll
import PySec
input("Go")
a = cdll.LoadLibrary(r"C:\Users\markb\source\repos\PySec\Cross-PlatformCryptoLib\out\build\x64-Debug\Cross-PlatformCryptoLib.dll")
input("Go")

if a.Init() ==0:
    print("Error")
Encrypt = a.AESEncrypt
Encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
Encrypt.restype = tuple
input("Go")
a = os.urandom(32)
print(a)
strbuff = ctypes.create_string_buffer
print(b"fgf")
buff = strbuff(b"fgf")
buffa=strbuff(os.urandom(32))
result = Encrypt(buff,buffa)
print(result)