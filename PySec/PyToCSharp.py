import sys
import ctypes
import os
from ctypes import cdll
import PySec
input("Go")
a = cdll.LoadLibrary(r"x64/Debug/CppDotNet.dll")
input("Go")
a.Init()
input("Go")
Encrypt = a.AesEncryptPy
Encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
Encrypt.restype = tuple
input("Go")
a = os.urandom(32)
print(a)
print(b"fgf")
print(Encrypt(b"fgf",os.urandom(32)))