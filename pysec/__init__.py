import hashlib
import sqlite3
import sys
import ctypes
import sys

DEBUG = True
if sys.platform == "win32" and DEBUG:
    sys.path.append(r"out\build\x64-Debug\Debug")
    sys.path.append(r"CryptoLib\build\Debug")
elif sys.platform == "win32" and not DEBUG:
    sys.path.append(r"CryptoLib\out\build\x64-Release\RelWithDebInfo")
    sys.path.append(r"CryptoLib\build\Release")
elif sys.platform != "win32" and DEBUG:
    sys.path.append(r"CryptoLib\out\build\Linux-Clang-Debug")
else:
    sys.path.append(r"CryptoLib\out\build\Linux-Clang-Release")


version = "1"

__all__ = ["Basic"]
ignore = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__']
search = 9


from .Basic import kms

KMS:kms = kms()
