import os
import pathlib
import sys
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
OPENSSL_CONFIG = os.path.join(sitePackages,"openssl-config")
OPENSSL_BIN = os.path.join(sitePackages, "openssl-install/bin")
OPENSSL_MODULES = os.path.join(sitePackages, "openssl-install/lib/ossl-modules")
cryptoDBLocation = os.path.join(sitePackages, "pysec/crypto.db")
os.add_dll_directory(OPENSSL_BIN)
os.add_dll_directory(OPENSSL_MODULES)
os.environ["OPENSSL_MODULES"] = OPENSSL_MODULES
os.environ["OPENSSL_CONF"] = os.path.join(OPENSSL_CONFIG,"openssl.cnf")
os.environ["OPENSSL_CONF_INCLUDE"] = OPENSSL_CONFIG
