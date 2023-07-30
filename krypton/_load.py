"""
Load up databases, and configure OSSL FIPS module.
"""
# pylint: disable=cyclic-import
# pylint: disable=invalid-name

import os
import sys
import pathlib
import ctypes
import subprocess
import importlib.metadata
from sqlalchemy import (
    DateTime,
    Text,
    create_engine,
    Column,
    Integer,
    LargeBinary,
    select,
    Boolean,
)
from sqlalchemy.orm import declarative_base, Session, sessionmaker

__version__ = importlib.metadata.version("krptn")

print(
    "Hey there! Welcome from Krptn. We are setting up some things for you. "
    "In case you run into any problems, please read our "
    "common issues guide: https://docs.krptn.dev/README-FAQ.html. "
    "It is more complete than you think!"
)

SITE_PACKAGE = pathlib.Path(__file__).parent.parent.as_posix()
USER_DIR = pathlib.Path.home()

OPENSSL_INSTALL_PREFIX = os.environ.get("KR_OPENSSL_INSTALL", "kr-openssl-install")
OPENSSL_INSTALL_DIR = os.path.join(SITE_PACKAGE, OPENSSL_INSTALL_PREFIX)
OPENSSL_CONFIG = pathlib.Path(SITE_PACKAGE, "kr-openssl-config").as_posix()
OPENSSL_CONFIG_FILE = pathlib.Path(OPENSSL_CONFIG, "openssl.cnf").as_posix()
OPENSSL_BIN = os.path.join(OPENSSL_INSTALL_DIR, "bin")
OPENSSL_EXE = os.path.join(
    OPENSSL_BIN, "openssl.exe" if sys.platform == "win32" else "openssl"
)
OSSL_LIB = os.path.join(OPENSSL_INSTALL_DIR, "lib")
if not pathlib.Path(OSSL_LIB).exists() and sys.platform == "linux":
    OSSL_LIB = os.path.join(OPENSSL_INSTALL_DIR, "lib64")
OPENSSL_MODULES = os.path.join(OSSL_LIB, "ossl-modules")
OPENSSL_FIPS_MODULE = os.path.join(
    OPENSSL_MODULES,
    "fips.dll"
    if sys.platform == "win32"
    else ("fips.so" if sys.platform == "linux" else "fips.dylib"),
)
OPENSSL_FIPS_CONF = os.path.join(OPENSSL_CONFIG, "fipsmodule.cnf")

KR_DATA = pathlib.Path(pathlib.Path.home(), ".krptn-data/")
if not KR_DATA.exists():
    os.mkdir(KR_DATA.as_posix())
try:
    os.remove(OPENSSL_CONFIG_FILE)
except FileNotFoundError:
    pass

if sys.platform == "linux":
    subprocess.call(["/sbin/ldconfig", OSSL_LIB])
subprocess.call(
    [
        OPENSSL_EXE,
        "fipsinstall",
        "-out",
        OPENSSL_FIPS_CONF,
        "-module",
        OPENSSL_FIPS_MODULE,
    ]
)

OSSL_CONF = f"""
config_diagnostics = 1
openssl_conf = openssl_init

.include {pathlib.Path(OPENSSL_FIPS_CONF).as_posix()}

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

# Alone, it will never find these
if sys.platform == "win32":
    os.add_dll_directory(SITE_PACKAGE)
    os.add_dll_directory(OPENSSL_BIN)
    os.add_dll_directory(OPENSSL_MODULES)
elif sys.platform == "linux":
    ctypes.CDLL(os.path.join(OSSL_LIB, "libcrypto.so.3"))
elif sys.platform == "darwin":
    ctypes.CDLL(os.path.join(OSSL_LIB, "libcrypto.dylib"))

Base = declarative_base()


class DBschemas:  # pylint: disable=too-few-public-methods
    """Database Schema"""

    class CryptoTable(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        - id: int
        - ctext: bytes
        - salt: bytes
        - cipher: str
        - saltIter: int"""

        __tablename__ = "crypto"
        id = Column(Integer, primary_key=True)
        ctext = Column(LargeBinary)
        salt = Column(LargeBinary)
        cipher = Column(Text)
        saltIter = Column(Integer)

    class KeysTable(Base):  # pylint: disable=too-few-public-methods
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
        name = Column(Text(450), index=True)
        key = Column(LargeBinary)
        salt = Column(LargeBinary)
        cipher = Column(Text)
        saltIter = Column(Integer)
        year = Column(Integer)

    class PubKeyTable(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        Uid: int
        key: str
        krVersion: str"""

        __tablename__ = "pubKeys"
        id = Column(Integer, primary_key=True)
        Uid = Column(Integer, index=True)
        krVersion = Column(Text, default=__version__)
        key = Column(Text)

    class UserTable(Base):  # pylint: disable=too-few-public-methods
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
        name = Column(Text(450), index=True)
        pwdAuthToken = Column(Text)
        mfa = Column(LargeBinary, default=b"*")
        fidoPub = Column(LargeBinary, default=b"*")
        fidoID = Column(LargeBinary, default=b"*")
        fidoChallenge = Column(LargeBinary, default=b"*")

    class SessionKeys(Base):  # pylint: disable=too-few-public-methods
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

    class UserData(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        Uid: int
        name: str
        value: bytes
        shared: int, default=0"""

        __tablename__ = "userData"
        id = Column(Integer, primary_key=True)
        Uid = Column(Integer, index=True)
        name = Column(Text(450), index=True)
        value = Column(LargeBinary)

    class UserShareTable(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        sender: int
        name: bytes
        salt: bytes
        value: bytes
        shareUid: int"""

        __tablename__ = "userShareData"
        id = Column(Integer, primary_key=True)
        sender = Column(Integer, index=True)
        name = Column(Text(450), index=True)
        salt = Column(LargeBinary)
        value = Column(LargeBinary)
        shareUid = Column(Integer, index=True)

    class PWDReset(Base):  # pylint: disable=too-few-public-methods
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

    class Logs(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        logId: int,
        time: DaeTime,
        exp: DateTime,
        success: bool
        userId: int
        """

        __tablename__ = "logs"
        logId = Column(Integer, primary_key=True)
        time = Column(DateTime)
        exp = Column(DateTime)
        success = Column(Boolean)
        userId = Column(Integer, index=True)


class ConfigTemp:
    """Configuration templates"""

    defaultAlgorithm = "AES256GCM"
    APP_NAME = "KryptonApp"
    HOST_NAME = ""
    ORIGIN = ""
    defaultIterations = 800000
    defaultPasswordResetIterations = 850000
    defaultCryptoperiod = 2
    defaultSessionPeriod = 15  # Minutes
    defaultLogRetentionPeriod = 43200  # Minutes
    _saltLen = 16
    _aesKeyLen = 32
    _cryptoDB: sessionmaker = None
    _cryptoDbEngine = None
    _altKeyDB: sessionmaker = None
    _altKeyDbEngine = None
    _userDB: sessionmaker = None
    _userDbEngine = None

    @property
    def SQLDefaultCryptoDBpath(self) -> Session:
        """
        Connection to the default database used with Crypto Class
        """
        return self._cryptoDB

    @SQLDefaultCryptoDBpath.setter
    def SQLDefaultCryptoDBpath(self, path: str) -> None:
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
                id=1,
                ctext=b"Position Reserved",
                salt=b"Position Reserved",
                cipher="None",
                saltIter=0,
            )
            c.add(stmt)
        c.autoflush = True
        c.flush()
        c.commit()
        c.close()
        self._cryptoDbEngine = engine
        self._cryptoDB = sessionmaker(engine, autoflush=True)

    @property
    def SQLDefaultKeyDBpath(self) -> Session:
        """
        Connection to the default database used by the KMS
        """
        return self._altKeyDB

    @SQLDefaultKeyDBpath.setter
    def SQLDefaultKeyDBpath(self, path: str):
        """
        Connection to the default database used by the KMS
        """
        engine = create_engine(path, echo=False, future=True)
        c = Session(engine)
        Base.metadata.create_all(engine)
        c.autoflush = True
        c.commit()
        c.flush()
        c.close()
        self._altKeyDbEngine = engine
        self._altKeyDB = sessionmaker(engine, autoflush=True)

    @property
    def SQLDefaultUserDBpath(self) -> Session:
        """
        Connection to the default database used to store User Data.
        """
        return self._userDB

    @SQLDefaultUserDBpath.setter
    def SQLDefaultUserDBpath(self, path: str):
        """
        Connection to the default database used to store User Data.
        """
        engine = create_engine(path, echo=False, future=True)
        c = Session(engine)
        Base.metadata.create_all(engine)
        error = False

        stmt = select(DBschemas.UserTable).where(
            DBschemas.UserTable.id == 1
        )  # Has to be one because of shared
        test = None
        try:
            test = c.scalar(stmt)
        except:
            error = True
        if test is None or error:
            stmt = DBschemas.UserTable(
                id=1, name="Position Reserved", pwdAuthToken=b"Position Reserved"
            )
            c.add(stmt)
        c.autoflush = True
        c.flush()
        c.commit()
        c.close()
        self._userDbEngine = engine
        self._userDB = sessionmaker(engine, autoflush=True)


configs = ConfigTemp()

configs.SQLDefaultCryptoDBpath = "sqlite+pysqlite:///" + os.path.join(
    USER_DIR, ".krptn-data/crypto.db"
)
configs.SQLDefaultKeyDBpath = "sqlite+pysqlite:///" + os.path.join(
    USER_DIR, ".krptn-data/altKMS.db"
)
configs.SQLDefaultUserDBpath = "sqlite+pysqlite:///" + os.path.join(
    USER_DIR, ".krptn-data/users.db"
)

# configs.SQLDefaultUserDBpath = "mssql+pyodbc://localhost/userDB?driver=ODBC+Driver+18+for+SQL+Server&encrypt=no"
