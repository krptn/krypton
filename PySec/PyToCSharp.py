import sys
import ctypes
import os
from ctypes import cdll
import PySec
a = cdll.LoadLibrary(r"x64/Debug/CppDotNet.dll")
input("Go")
a.Init()
input("Go")
Encrypt = a.AesEncryptPy
Encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
Encrypt.restype = tuple
adder = a.test
input("Go")
adder.argtypes = [ctypes.c_int, ctypes.c_int]
input("Go")
print(Encrypt(b"fgf"),os.urandom(32))
