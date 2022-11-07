"""
Load up databases, and set configuration needed by OPENSSL FIPS module.
"""
# pylint: disable=cyclic-import
# pylint: disable=invalid-name

import os
import sys
import pathlib
import ctypes
from sqlalchemy import DateTime, Text, create_engine, Column, Integer, LargeBinary, select
from sqlalchemy.orm import declarative_base, Session, sessionmaker

SITE_PACKAGE = pathlib.Path(__file__).parent.parent.as_posix()

OPENSSL_CONFIG = os.path.join(SITE_PACKAGE, "kr-openssl-config")
OPENSSL_CONFIG_FILE = os.path.join(OPENSSL_CONFIG, "openssl.cnf")
OPENSSL_BIN = os.path.join(SITE_PACKAGE, "kr-openssl-install/bin")
OPENSSL_EXE = os.path.join(OPENSSL_BIN, "openssl.exe" if sys.platform == "win32" else "openssl")
LINUX_OSSL_LIB = os.path.join(SITE_PACKAGE, "kr-openssl-install/lib64")
MAC_OSSL_LIB = os.path.join(SITE_PACKAGE, "kr-openssl-install/lib")
RELATIVE_OSSL_MOD = ("kr-openssl-install/lib64/ossl-modules" if sys.platform == "linux"
    else "kr-openssl-install/lib/ossl-modules")
OPENSSL_MODULES = os.path.join(SITE_PACKAGE, RELATIVE_OSSL_MOD)
USER_DIR = pathlib.Path.home()

os.environ["OPENSSL_MODULES"] = OPENSSL_MODULES
os.environ["OPENSSL_CONF"] = OPENSSL_CONFIG_FILE
os.environ["OPENSSL_CONF_INCLUDE"] = OPENSSL_CONFIG
os.environ["OPENSSL"] = OPENSSL_BIN

if sys.platform == "win32":
    os.add_dll_directory(OPENSSL_BIN)
    os.add_dll_directory(OPENSSL_MODULES)
elif sys.platform == "linux":
    ctypes.CDLL(os.path.join(LINUX_OSSL_LIB, "libcrypto.so.3")) # Alone, it will never find these
elif sys.platform == "darwin":
    ctypes.CDLL(os.path.join(MAC_OSSL_LIB, "libcrypto.dylib")) # Alone, it will never find these

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
        name = Column(Text, index=True)
        key = Column(LargeBinary)
        salt = Column(LargeBinary)
        cipher = Column(Text)
        saltIter = Column(Integer)
        year = Column(Integer)

    class PubKeyTable(Base): # pylint: disable=too-few-public-methods
        """Database Schema
        Uid: int
        key: str"""
        __tablename__ = "pubKeys"
        id = Column(Integer, primary_key=True)
        Uid = Column(Integer, index=True)
        key = Column(Text)

    class UserTable(Base): # pylint: disable=too-few-public-methods
        """Database
        id: int
        name: str
        pwdAuthToken: bytes,
        salt: bytes,
        mfa: bytes,
        fidoPub: bytes,
        fidoID: bytes"""
        __tablename__ = "users"
        id = Column(Integer, primary_key=True)
        name = Column(Text, index=True)
        pwdAuthToken = Column(Text)
        mfa = Column(LargeBinary, default=b"*")
        fidoPub = Column(LargeBinary, default=b"*")
        fidoID = Column(LargeBinary, default=b"*")
        fidoChallenge = Column(LargeBinary, default=b"*")

    class SessionKeys(Base): # pylint: disable=too-few-public-methods
        """Database Schema
        id: int
        Uid: int
        key: str
        exp: DateTime
        iss: DateTime"""
        __tablename__ = "sessions"
        id = Column(Integer, primary_key=True)
        Uid = Column(Integer, index=True)
        key = Column(LargeBinary)
        exp = Column(DateTime, index=True)
        iss = Column(DateTime)

    class UserData(Base): # pylint: disable=too-few-public-methods
        """Database Schema
        Uid: int
        name: str
        value: bytes
        shared: int, default=0"""
        __tablename__ = "userData"
        id = Column(Integer, primary_key=True)
        Uid = Column(Integer, index=True)
        name = Column(Text, index=True)
        value = Column(LargeBinary)
    
    class UserShareTable(Base): # pylint: disable=too-few-public-methods
        """Database Schema
        sender: int
        name: bytes
        salt: bytes
        value: bytes
        shareUid: int"""
        __tablename__ = "userShareData"
        id = Column(Integer, primary_key=True)
        sender = Column(Integer, index=True)
        name = Column(Text, index=True)
        salt = Column(LargeBinary)
        value = Column(LargeBinary)
        shareUid = Column(Integer, index=True)

    class PWDReset(Base): # pylint: disable=too-few-public-methods
        """Database Schema
        Uid: int,
        key: bytes,
        iter: int,
        salt: bytes
        """
        __tablename__ = "pwdReset"
        id = Column(Integer, primary_key=True)
        Uid = Column(Integer, index=True)
        key = Column(LargeBinary)
        iter = Column(Integer)
        salt = Column(LargeBinary)

class ConfigTemp():
    """Configuration templates"""
    defaultAlgorithm = "AES256GCM"
    APP_NAME = "KryptonApp"
    HOST_NAME = ""
    ORIGIN = ""
    defaultIterations = 500000
    defaultPasswordResetIterations = 800000
    defaultCryptoperiod = 2
    defaultSessionPeriod = 15 # Minutes
    _cryptoDB:sessionmaker = None
    _altKeyDB:sessionmaker = None
    _userDB:sessionmaker = None
    @property
    def SQLDefaultCryptoDBpath(self) -> Session:
        """
            Connection to the default database used with Crypto Class
        """
        return self._cryptoDB
    @SQLDefaultCryptoDBpath.setter
    def SQLDefaultCryptoDBpath(self, path:str) -> None:
        """
            Connection to the default database used with Crypto Class
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
        c.autoflush = True
        c.flush()
        c.commit()
        c.close()
        self._cryptoDB = sessionmaker(engine, autoflush=True)

    @property
    def SQLDefaultKeyDBpath(self) -> Session:
        """
            Connection to the default database used by the KMS
        """
        return self._altKeyDB
    @SQLDefaultKeyDBpath.setter
    def SQLDefaultKeyDBpath(self, path:str):
        """
            Connection to the default database used by the KMS
        """
        conn = create_engine(path, echo=False, future=True)
        c = Session(conn)
        Base.metadata.create_all(conn)
        c.autoflush = True
        c.commit()
        c.flush()
        c.close()
        self._altKeyDB = sessionmaker(conn, autoflush=True)

    @property
    def SQLDefaultUserDBpath(self) -> Session:
        """
            Connection to the default database used to store User Data.
        """
        return self._userDB
    @SQLDefaultUserDBpath.setter
    def SQLDefaultUserDBpath(self, path:str):
        """
            Connection to the default database used to store User Data.
        """
        engine = create_engine(path, echo=False, future=True)
        c = Session(engine)
        Base.metadata.create_all(engine)
        error = False

        stmt = select(DBschemas.UserTable).where(DBschemas.UserTable.id == 1) # Has to be one because of shared
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
        c.autoflush = True
        c.flush()
        c.commit()
        c.close()
        self._userDB = sessionmaker(engine, autoflush=True)

configs = ConfigTemp()

kr_data = pathlib.Path(pathlib.Path.home(), ".krptn-data/")
if not kr_data.exists():
    os.mkdir(kr_data.as_posix())

configs.SQLDefaultCryptoDBpath = "sqlite+pysqlite:///"+os.path.join(USER_DIR, ".krptn-data/crypto.db")
configs.SQLDefaultKeyDBpath = "sqlite+pysqlite:///"+os.path.join(USER_DIR, ".krptn-data/altKMS.db")
configs.SQLDefaultUserDBpath = "sqlite+pysqlite:///"+os.path.join(USER_DIR, ".krptn-data/users.db")

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

