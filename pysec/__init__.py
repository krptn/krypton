import os
import pathlib
import sqlite3
import sys
import basic
import _setups
version = "1"

__all__ = ["basic"]
ignore = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__']
search = 5

if sys.executable[-18:] == "Scripts\\python.exe":
    sitePackages = os.path.join(
        pathlib.Path(sys.executable).parent.parent.absolute(),
        "Lib\\site-packages"
    )
else:
    sitePackages = os.path.join(
        pathlib.Path(sys.executable).parent.absolute(),
        "Lib\\site-packages"
    )

OPENSSL_CONFIG = os.path.join(sitePackages, "openssl-config")
OPENSSL_CONFIG_FILE = os.path.join(OPENSSL_CONFIG, "openssl.cnf")
OPENSSL_BIN = os.path.join(sitePackages, "openssl-install/bin")
OPENSSL_MODULES = os.path.join(sitePackages, "openssl-install/lib/ossl-modules")

os.add_dll_directory(OPENSSL_BIN)
os.add_dll_directory(OPENSSL_MODULES)
os.environ["OPENSSL_MODULES"] = OPENSSL_MODULES
os.environ["OPENSSL_CONF"] = OPENSSL_CONFIG_FILE
os.environ["OPENSSL_CONF_INCLUDE"] = OPENSSL_CONFIG

defaultCryptoDBpath = property(
    fget=lambda: _cryptoDB,
    fset=_setups.setupCryptoDB,
    doc="Location of the default DB for crypto class"
)

defaultKeyDBpath = property(
    fget=lambda: _altKeyDB,
    fset=_setups.setupKeyDB,
    doc="Location of the default keydb for kms class"
)

userDBpath = property(
    fget=lambda: _userDB,
    fset=_setups.setupUserDB,
    doc="Location of the databse for users"
)

_cryptoDB:sqlite3.Connection
_altKeyDB:sqlite3.Connection
_userDB:sqlite3.Connection

defaultCryptoDBpath = os.path.join(sitePackages, "pysec-data/crypto.db")
defaultKeyDBpath = os.path.join(sitePackages, "pysec-data/altKMS.db")
