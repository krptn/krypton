import sys
import ctypes
import os
from ctypes import cdll
import PySec
a = cdll.LoadLibrary(r"x64/Debug/CppDotNet.dll")
a.Init()

#Encrypt = a.AesEncryptPy
#Encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
#Encrypt.restype = tuple
adder = a.test
adder.argtypes = [ctypes.c_int, ctypes.c_int]

import time
input("go")
print(adder(1,1))
input("go")