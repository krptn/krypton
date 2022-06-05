import os
import sys
import pathlib
from sqlalchemy import String, create_engine, Column, Integer, LargeBinary, select
from sqlalchemy.orm import declarative_base, Session
import sqlalchemy

SITE_PACKAGE = pathlib.Path(__file__).parent.parent.as_posix()

OPENSSL_CONFIG = os.path.join(SITE_PACKAGE, "openssl-config")
OPENSSL_CONFIG_FILE = os.path.join(OPENSSL_CONFIG, "openssl.cnf")
OPENSSL_BIN = os.path.join(SITE_PACKAGE, "openssl-install/bin")
OPENSSL_MODULES = os.path.join(SITE_PACKAGE, "openssl-install/lib/ossl-modules")

if sys.platform == "win32":
    os.add_dll_directory(OPENSSL_BIN)
    os.add_dll_directory(OPENSSL_MODULES)
else:
    os.environ['PATH'] = OPENSSL_BIN + os.pathsep + OPENSSL_MODULES + os.pathsep + os.environ['PATH']
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
        cipher = Column(String(20)) # We should not need more then this
        saltIter = Column(Integer)

    class keysTable(Base):
        __tablename__ = "keys"
        id = Column(Integer, primary_key=True)
        name = Column(String(20))
        key = Column(LargeBinary)
        salt = Column(LargeBinary)
        cipher = Column(String(20))
        saltIter = Column(Integer)
        year = Column(Integer)

    class pubKeyTable(Base):
        __tablename__ = "pubKeys"
        number = Column(Integer, primary_key=True)
        name = Column(String(44))
        key = Column(LargeBinary)

    class userTable(Base):
        __tablename__ = "users"
        number = Column(Integer, primary_key=True)
        name = Column(String(44))
        id = Column(LargeBinary)

class configTemp():
    defaultAlgorithm = "AES256GCM"
    defaultIterations = 500000
    defaultCryptoperiod = 2
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
        engine = create_engine(path, echo=False, future=True)
        c = Session(engine)
        Base.metadata.create_all(engine)
        error = False
        stmt = select(DBschemas.cryptoTable).where(DBschemas.cryptoTable.id == 1)
        x = None
        try: x = c.scalar(stmt)
        except: error = True
        if x == None or error:
            stmt = DBschemas.cryptoTable(
                id = 1,
                ctext = b"Position Reserved",
                salt = b"Position Reserved",
                cipher = "None",
                saltIter = 0
            )
            c.add(stmt)
        c.commit()
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
        conn = create_engine(path, echo=False, future=True)
        c = Session(conn)
        Base.metadata.create_all(conn)
        c.commit()
        self._altKeyDB = c

    @property
    def SQLDefaultUserDBpath(self):
        """
            Connection to the default database used to store User Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        return self._userDB
    @SQLDefaultUserDBpath.setter
    def SQLDefaultUserDBpath(self, path:str):
        engine = create_engine(path, echo=False, future=True)
        c = Session(engine)
        Base.metadata.create_all(engine)
        c.commit()
        self._userDB = c

configs = configTemp()

configs.SQLDefaultCryptoDBpath = "sqlite+pysqlite:///"+os.path.join(SITE_PACKAGE, "pysec-data/crypto.db")
configs.SQLDefaultKeyDBpath = "sqlite+pysqlite:///"+os.path.join(SITE_PACKAGE, "pysec-data/altKMS.db")
configs.SQLDefaultUserDBpath = "sqlite+pysqlite:///"+os.path.join(SITE_PACKAGE, "pysec-data/users.db")

#configs.SQLDefaultCryptoDBpath = "mssql+pyodbc://localhost/crypto?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=no"
#configs.SQLDefaultCryptoDBpath = "postgresql+psycopg2://example:example@localhost:5432/example"
#configs.SQLDefaultCryptoDBpath = "mysql+mysqldb://test:test@localhost:3306/cryptodb"

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
