"""
Loads up databases and sets configuration needed by OPENSSL FIPS module.
"""
import os
import sys
import pathlib
import ctypes
from sqlalchemy import DateTime, Text, create_engine, Column, Integer, LargeBinary, select
from sqlalchemy.orm import declarative_base, Session

SITE_PACKAGE = pathlib.Path(__file__).parent.parent.as_posix()

OPENSSL_CONFIG = os.path.join(SITE_PACKAGE, "kr-openssl-config")
OPENSSL_CONFIG_FILE = os.path.join(OPENSSL_CONFIG, "openssl.cnf")
OPENSSL_BIN = os.path.join(SITE_PACKAGE, "kr-openssl-install/bin")
OPENSSL_EXE = os.path.join(OPENSSL_BIN, "openssl.exe" if sys.platform == "win32" else "openssl")
LINUX_OSSL_LIB = os.path.join(SITE_PACKAGE, "kr-openssl-install/lib64")
RELATIVE_OSSL_MOD = ("kr-openssl-install/lib/ossl-modules" if sys.platform == "win32"
    else "kr-openssl-install/lib64/ossl-modules")
OPENSSL_MODULES = os.path.join(SITE_PACKAGE, RELATIVE_OSSL_MOD)
USER_DIR = pathlib.Path.home()

if sys.platform == "win32":
    os.add_dll_directory(OPENSSL_BIN)
    os.add_dll_directory(OPENSSL_MODULES)
else:
    ctypes.CDLL(os.path.join(LINUX_OSSL_LIB, "libcrypto.so.3")) # Alone, it will never find this
    ctypes.CDLL(os.path.join(LINUX_OSSL_LIB, "libssl.so.3"))
os.environ["OPENSSL_MODULES"] = OPENSSL_MODULES
os.environ["OPENSSL_CONF"] = OPENSSL_CONFIG_FILE
os.environ["OPENSSL_CONF_INCLUDE"] = OPENSSL_CONFIG
os.environ["OPENSSL"] = OPENSSL_BIN

Base = declarative_base()

class DBschemas(): # pylint: disable=too-few-public-methods
    """Database Schema"""
    class CryptoTable(Base): # pylint: disable=too-few-public-methods
        """Database Schema
        - id: int
        - ctext: bytes
        - salt: bytes
        - cipher: str
        - saltIter: int"""
        __tablename__="crypto"
        id = Column(Integer, primary_key=True)
        ctext = Column(LargeBinary)
        salt = Column(LargeBinary)
        cipher = Column(Text)
        saltIter = Column(Integer)

    class KeysTable(Base): # pylint: disable=too-few-public-methods
        """Database Schema
        id: int
        name: str
        key: bytes
        salt: bytes
        cipher: str
        saltIter: int
        year: int"""
        __tablename__ = "keys"
        id = Column(Integer, primary_key=True)
        name = Column(Text)
        key = Column(LargeBinary)
        salt = Column(LargeBinary)
        cipher = Column(Text)
        saltIter = Column(Integer)
        year = Column(Integer)

    class PubKeyTable(Base): # pylint: disable=too-few-public-methods
        """Database Schema
        id: int
        name: str
        key: bytes"""
        __tablename__ = "pubKeys"
        id = Column(Integer, primary_key=True)
        name = Column(Text)
        key = Column(Text)

    class UserTable(Base): # pylint: disable=too-few-public-methods
        """Database 
        id: int
        name: str
        pwdAuthToken: bytes,
        salt: bytes"""
        __tablename__ = "users"
        id = Column(Integer, primary_key=True)
        name = Column(Text)
        pwdAuthToken = Column(Text)
        salt = Column(LargeBinary)
    
    class SessionKeys(Base): # pylint: disable=too-few-public-methods
        """Database Schema
        id: int
        Uid: bytes
        key: str
        exp: DateTime
        iss: DateTime"""
        __tablename__ = "sessions"
        id = Column(Integer, primary_key=True)
        key = Column(Text)
        exp = Column(DateTime)
        iss = Column(DateTime)
    
    class UserData(Base): # pylint: disable=too-few-public-methods
        """Database Schema -- This is ugly.
        Uid: int
        name: bytes
        value: bytes"""
        __tablename__ = "userData"
        id = Column(Integer, primary_key=True)
        Uid = Column(Integer)
        name = Column(LargeBinary)
        value = Column(LargeBinary)
    
    class KrConfig(Base): # pylint: disable=too-few-public-methods
        """Database Schema
        name: str
        value: bytes"""
        __tablename__ = "krconfig"
        id = Column(Integer, primary_key=True)
        name = Column(Text)
        value = Column(Text)
    
class ConfigTemp():
    """Configuration templates"""
    defaultAlgorithm = "AES256GCM"
    defaultIterations = 500000
    defaultErrorPage = ""
    defaultCryptoperiod = 2
    defaultSessionPeriod = 15 # Minutes
    _cryptoDB:Session = None
    _altKeyDB:Session = None
    _userDB:Session = None
    @property
    def SQLDefaultCryptoDBpath(self) -> Session:
        """
            Connection to the default database used to store Encrypted Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        return self._cryptoDB
    @SQLDefaultCryptoDBpath.setter
    def SQLDefaultCryptoDBpath(self, path:str) -> None:
        """
            Connection to the default database used to store Encrypted Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        engine = create_engine(path, echo=False, future=True)
        c = Session(engine)
        Base.metadata.create_all(engine)
        error = False
        stmt = select(DBschemas.CryptoTable).where(DBschemas.CryptoTable.id == 1)
        test = None
        try:
            test = c.scalar(stmt)
        except:
            error = True
        if test is None or error:
            stmt = DBschemas.CryptoTable(
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
    def SQLDefaultKeyDBpath(self) -> Session:
        """
            Connection to the default database used to store Keys.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        return self._altKeyDB
    @SQLDefaultKeyDBpath.setter
    def SQLDefaultKeyDBpath(self, path:str):
        """
            Connection to the default database used to store Encrypted Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        conn = create_engine(path, echo=False, future=True)
        c = Session(conn)
        Base.metadata.create_all(conn)
        c.commit()
        self._altKeyDB = c

    @property
    def SQLDefaultUserDBpath(self) -> Session:
        """
            Connection to the default database used to store User Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        return self._userDB
    @SQLDefaultUserDBpath.setter
    def SQLDefaultUserDBpath(self, path:str):
        """
            Connection to the default database used to store Encrypted Data.
            Either set a string for sqlite3 database or Connection object for other databases.
        """
        engine = create_engine(path, echo=False, future=True)
        c = Session(engine)
        Base.metadata.create_all(engine)
        error = False

        stmt = select(DBschemas.UserTable).where(DBschemas.UserTable.id == 1)
        test = None
        try:
            test = c.scalar(stmt)
        except:
            error = True
        if test is None or error:
            stmt = DBschemas.UserTable(
                id = 1,
                name = "Position Reserved",
                pwdAuthToken = b"Position Reserved"
            )
            c.add(stmt)
        c.commit()
        self._userDB = c

configs = ConfigTemp()

configs.SQLDefaultCryptoDBpath = "sqlite+pysqlite:///"+os.path.join(USER_DIR, ".krypton-data/crypto.db")
configs.SQLDefaultKeyDBpath = "sqlite+pysqlite:///"+os.path.join(USER_DIR, ".krypton-data/altKMS.db")
configs.SQLDefaultUserDBpath = "sqlite+pysqlite:///"+os.path.join(USER_DIR, ".krypton-data/users.db")

#configs.SQLDefaultUserDBpath = "mssql+pyodbc://localhost/userDB?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=no"
#configs.SQLDefaultCryptoDBpath = "postgresql+psycopg2://example:example@localhost:5432/example"
#configs.SQLDefaultCryptoDBpath = "mysql+mysqldb://test:test@localhost:3306/cryptodb"

OSSL_CONF = """
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
"""

with open(OPENSSL_CONFIG_FILE, "w") as file:
    file.write(OSSL_CONF)

stmt = select(DBschemas.KrConfig.value).where(DBschemas.KrConfig.name == "SALT")
Globalsalt = configs.SQLDefaultCryptoDBpath.scalar(stmt)
if Globalsalt == None:
    Globalsalt = os.urandom(12)
    entry = DBschemas.KrConfig(
        name = "SALT",
        value = Globalsalt
    )
    configs.SQLDefaultCryptoDBpath.add(entry)
configs.SQLDefaultCryptoDBpath.commit()
