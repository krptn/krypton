'''
https://www.krptn.dev/

A user authentication and access management system (IAM) with [Zero Knowledge security](/news/zero-knowledge/).

How we achieve this?

- All Data is encrypted (any data can be request by the developer to be secured)
- Only the appropriate users' credentials can unlock the cryptosystem (this protects you from server-side attacks)
'''
# pylint: disable=cyclic-import

from ._load import *
from . import basic
from . import auth

__all__ = ['basic', 'auth']
ignore = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__',
    '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__',
    '__init__', '__init_subclass__', '__le__', '__lt__', '__module__',
    '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__',
    '__sizeof__', '__str__', '__subclasshook__', '__weakref__']
search = 5
