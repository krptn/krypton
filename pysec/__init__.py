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

SQLDefaultCryptoDBpath = property(
    fget=lambda: __cryptoDB,
    fset=_setups.setupCryptoDB,
    doc=
    """
        Connection to the default database used to store Encrypted Data.
        Either set a string for sqlite3 database or Connection object for other databases.
    """
)

SQLDefaultKeyDBpath = property(
    fget=lambda: __altKeyDB,
    fset=_setups.setupKeyDB,
    doc=    
    """
        Connection to the default database used to store Keys.
        Either set a string for sqlite3 database or Connection object for other databases.
    """
)

SQLDefaultUserDBpath = property(
    fget=lambda: __userDB,
    fset=_setups.setupUserDB,
    doc=
    """
        Connection to the default database used to store User Data.
        Either set a string for sqlite3 database or Connection object for other databases.
    """
)

__cryptoDB:sqlite3.Connection
__altKeyDB:sqlite3.Connection
__userDB:sqlite3.Connection

SQLDefaultCryptoDBpath = os.path.join(sitePackages, "pysec-data/crypto.db")
SQLDefaultKeyDBpath = os.path.join(sitePackages, "pysec-data/altKMS.db")
SQLDefaultUserDBpath = os.path.join(sitePackages, "pysec-data/users.db")
