'''
https://github.com/krptn/krypton

A user authentication and access management system based entirely on cryptographic primitives.

What we mean by that is:

- All Data is encrypted (any data can be request by the developer to be secured)

- Only the appropriate users' credentials can unlock the cryptosystem
'''
# pylint: disable=cyclic-import

from ._load import *
from . import basic
from . import auth

version = '1'

__all__ = ['basic', 'auth']
ignore = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__',
    '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__',
    '__init__', '__init_subclass__', '__le__', '__lt__', '__module__',
    '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__',
    '__sizeof__', '__str__', '__subclasshook__', '__weakref__']
search = 5
