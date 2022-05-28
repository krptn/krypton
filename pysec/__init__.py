import os
import pathlib
from select import select
from sqlalchemy import MetaData, String, create_engine, Column, Integer, LargeBinary
from sqlalchemy.orm import declarative_base, Session
import sqlalchemy

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

Base = declarative_base()

class DBschemas():
    class cryptoTable(Base):
        __tablename__="crypto"
        id = Column(Integer, primary_key=True)
        ctext = Column(LargeBinary)
        salt = Column(LargeBinary)
        cipher = Column(String)
        saltIter = Column(Integer)

    class keysTable(Base):
        __tablename__ = "keys"
        name = Column(String, primary_key=True)
        key = Column(LargeBinary)
        salt = Column(LargeBinary)
        cipher = Column(String)
        saltIter = Column(Integer)

    class pubKeyTable(Base):
        __tablename__ = "pubKeys"
        name = Column(String, primary_key=True)
        key = Column(LargeBinary)

    class userTable(Base):
        __tablename__ = "users"
        name = Column(String, primary_key=True)
        id = Column(LargeBinary)

class configTemp():
    defaultAlgorithm = "AES256GCM"
    defaultIterations = 500000
    _cryptoDB:sqlalchemy.engine = None
    _altKeyDB:sqlalchemy.engine = None
    _userDB:sqlalchemy.engine = None
    @property
    def SQLDefaultCryptoDBpath(self):
        """
            Connection to the default database used to store Encrypted Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        return self._cryptoDB
    @SQLDefaultCryptoDBpath.setter
    def SQLDefaultCryptoDBpath(self, path:str) -> None:
        engine = create_engine(path, echo=True, future=True)
        c = Session(engine)
        try:
            Base.metadata.create_all(engine)
            stmt = select(DBschemas.cryptoTable).where(DBschemas.cryptoTable.id.in_(["0"]))
            ctext = self.c.scalar(stmt).one()
            if ctext == None:
                stmt = DBschemas.cryptoTable(
                    id = 0,
                    ctext = b"Position Reserved",
                    salt = b"Position Reserved",
                    cipher = "None",
                    saltIter = 0
                )
                c.add(stmt)
        except:
            pass
        finally:
            self._cryptoDB = c

    @property
    def SQLDefaultKeyDBpath(self):
        """
            Connection to the default database used to store Keys.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        return self._altKeyDB
    @SQLDefaultKeyDBpath.setter
    def SQLDefaultKeyDBpath(self, path:str):
        conn = create_engine(path, echo=True, future=True)
        try:
            Base.metadata.create_all(conn)
        except:
            pass
        self._altKeyDB = Session(conn)

    @property
    def SQLDefaultUserDBpath(self):
        """
            Connection to the default database used to store User Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        return self._userDB
    @SQLDefaultUserDBpath.setter
    def SQLDefaultUserDBpath(self, path:str):
        engine = create_engine(path, echo=True, future=True)
        c = Session(engine)
        try:
            Base.metadata.create_all(engine)
            stmt = select(DBschemas.cryptoTable).where(DBschemas.cryptoTable.id == 0)
            ctext = self.c.scalar(stmt).one()
            if ctext == None:
                stmt = DBschemas.cryptoTable(
                    id = 0,
                    ctext = b"Position Reserved",
                    salt = b"Position Reserved",
                    cipher = "None",
                    saltIter = 0
                )
                c.add(stmt)
        except:
            pass
        finally:
            self._userDB = c

configs = configTemp()

configs.SQLDefaultCryptoDBpath = "sqlite+pysqlite:///"+os.path.join(sitePackage, "pysec-data/crypto.db")
configs.SQLDefaultKeyDBpath = "sqlite+pysqlite:///"+os.path.join(sitePackage, "pysec-data/altKMS.db")
configs.SQLDefaultUserDBpath = "sqlite+pysqlite:///"+os.path.join(sitePackage, "pysec-data/users.db")

open(OPENSSL_CONFIG_FILE, "w").write("""
config_diagnostics = 1
openssl_conf = openssl_init

.include fipsmodule.cnf

[openssl_init]
providers = provider_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1
""")