import os
import pathlib
import sqlite3

version = "1"

__all__ = ["basic"]
ignore = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__']
search = 5

def __setupCryptoDB(path:str|sqlite3.Connection) -> None:
    global _cryptoDB
    if isinstance(path,str):
        conn = sqlite3.connect(path)
    else:
        conn = path
    c = conn.cursor()
    try:
        c.execute("CREATE TABLE crypto (id int, ctext blob)")
        c.execute("INSERT INTO crypto VALUES (?, ?)", (0, b"Position Reserved"))
        c.execute("CREATE TABLE keys (name text, key blob)")
    except:
        pass

    finally:
        conn.commit()
        c.close()
        _cryptoDB = conn

# Setup DB for kms class. 
def __setupKeyDB(path:str|sqlite3.Connection):
    global _altKeyDB
    if isinstance(path,str):
        conn = sqlite3.connect(path)
    else:
        conn = path
    c = conn.cursor()
    try:
        c.execute("CREATE TABLE keys (name text, key blob)")
    except:
        pass
    finally:
        conn.commit()
        c.close()
        _altKeyDB = conn

def __setupUserDB(path:str|sqlite3.Connection):
    global _userDB
    if isinstance(path,str):
        conn = sqlite3.connect(path)
    else:
        conn = path
        c = conn.cursor()
    try:
        c.execute("CREATE TABLE users (name text, id int)")
        c.execute("CREATE TABLE pubKeys (name text, key blob)")
    except:
        pass
    finally:
        conn.commit()
        c.close()
        conn.close()
        _userDB = conn

sitePackage = pathlib.Path(__file__).parent.parent.as_posix()

OPENSSL_CONFIG = os.path.join(sitePackage, "openssl-config")
OPENSSL_CONFIG_FILE = os.path.join(OPENSSL_CONFIG, "openssl.cnf")
OPENSSL_BIN = os.path.join(sitePackage, "openssl-install/bin")
OPENSSL_MODULES = os.path.join(sitePackage, "openssl-install/lib/ossl-modules")

os.add_dll_directory(OPENSSL_BIN)
os.add_dll_directory(OPENSSL_MODULES)
os.environ["OPENSSL_MODULES"] = OPENSSL_MODULES
os.environ["OPENSSL_CONF"] = OPENSSL_CONFIG_FILE
os.environ["OPENSSL_CONF_INCLUDE"] = OPENSSL_CONFIG

class configTemp():
    SQLDefaultCryptoDBpath = property(
        fget=lambda: _cryptoDB,
        fset=__setupCryptoDB,
        doc=
        """
            Connection to the default database used to store Encrypted Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
    )

    SQLDefaultKeyDBpath = property(
        fget=lambda: _altKeyDB,
        fset=__setupKeyDB,
        doc=    
        """
            Connection to the default database used to store Keys.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
    )

    SQLDefaultUserDBpath = property(
        fget=lambda: _userDB,
        fset=__setupUserDB,
        doc=
        """
            Connection to the default database used to store User Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
    )

    _cryptoDB:sqlite3.Connection
    _altKeyDB:sqlite3.Connection
    _userDB:sqlite3.Connection

configs = configTemp()

configs.SQLDefaultCryptoDBpath = os.path.join(sitePackage, "pysec-data/crypto.db")
configs.SQLDefaultKeyDBpath = os.path.join(sitePackage, "pysec-data/altKMS.db")
configs.SQLDefaultUserDBpath = os.path.join(sitePackage, "pysec-data/users.db")
