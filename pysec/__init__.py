import os
import pathlib
import sqlite3

version = "1"

__all__ = ["basic"]
ignore = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__']
search = 5

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
    _cryptoDB:sqlite3.Connection = sqlite3.connect(os.path.join(sitePackage, "pysec-data/crypto.db"))
    _altKeyDB:sqlite3.Connection = sqlite3.connect(os.path.join(sitePackage, "pysec-data/altKMS.db"))
    _userDB:sqlite3.Connection = sqlite3.connect(os.path.join(sitePackage, "pysec-data/users.db"))
    @property
    def SQLDefaultCryptoDBpath(self):
        """
            Connection to the default database used to store Encrypted Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        return self._cryptoDB
    @SQLDefaultCryptoDBpath.setter
    def SQLDefaultCryptoDBpath(self, path:str|sqlite3.Connection) -> None:
        if isinstance(path, str):
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
            self._cryptoDB = conn

    @property
    def SQLDefaultKeyDBpath(self):
        """
            Connection to the default database used to store Keys.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        return self._cryptoDB 
    @SQLDefaultKeyDBpath.setter
    def SQLDefaultKeyDBpath(self, path:str|sqlite3.Connection):
        if isinstance(path, str):
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
            self._altKeyDB = conn

    @property
    def SQLDefaultUserDBpath(self):
        """
            Connection to the default database used to store User Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        return self._userDB
    @SQLDefaultUserDBpath.setter
    def SQLDefaultUserDBpath(self, path:str|sqlite3.Connection):
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
            self._userDB = conn

configs = configTemp()

configs.SQLDefaultCryptoDBpath = os.path.join(sitePackage, "pysec-data/crypto.db")
configs.SQLDefaultKeyDBpath = os.path.join(sitePackage, "pysec-data/altKMS.db")
configs.SQLDefaultUserDBpath = os.path.join(sitePackage, "pysec-data/users.db")
