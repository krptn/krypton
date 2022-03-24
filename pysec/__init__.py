import hashlib
import sqlite3
import sys
import ctypes
import os
import pathlib
version = "1"

__all__ = ["Basic"]
ignore = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__']
search = 9

dll_path = pathlib.Path(__file__).parent.parent.absolute().as_posix()+pathlib.Path("/openssl-install/lib/oss-modules").as_posix()
os.environ['PATH'] = dll_path + os.pathsep + os.environ['PATH']
dll_path = pathlib.Path(__file__).parent.parent.absolute().as_posix()+pathlib.Path("/openssl-install/bin").as_posix()
os.environ['PATH'] = dll_path + os.pathsep + os.environ['PATH']

from .Basic import kms
KMS:kms = kms()
