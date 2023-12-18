"""
Load up databases, and configure Krptn.
"""
# pylint: disable=cyclic-import
# pylint: disable=invalid-name

import os
import pathlib
import importlib.metadata
from sqlalchemy import (
    DateTime,
    Index,
    Text,
    UniqueConstraint,
    create_engine,
    Column,
    Integer,
    LargeBinary,
    select,
    Boolean,
    ForeignKey,
)
from sqlalchemy.orm import declarative_base, Session, sessionmaker

__version__ = importlib.metadata.version("krptn")

USER_DIR = pathlib.Path.home()

MAX_USER_NAME_LEN = 450

KR_DATA = pathlib.Path(USER_DIR, ".krptn-data/")
if not KR_DATA.exists():
    os.mkdir(KR_DATA.as_posix())

Base = declarative_base()

USER_TABLE_NAME = "users"

class DBschemas:  # pylint: disable=too-few-public-methods
    """Database Schema"""

    class CryptoTable(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        - id: int
        - ctext: bytes
        - salt: bytes
        - saltIter: int"""

        __tablename__ = "crypto"
        id = Column(Integer, primary_key=True)
        ctext = Column(LargeBinary)
        salt = Column(LargeBinary)
        saltIter = Column(Integer)

    class KeysTable(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        id: int
        name: str
        key: bytes
        salt: bytes
        saltIter: int
        year: int"""

        __tablename__ = "keys"
        id = Column(Integer, primary_key=True)
        name = Column(Text(MAX_USER_NAME_LEN), index=True, unique=True)
        key = Column(LargeBinary)
        salt = Column(LargeBinary)
        saltIter = Column(Integer)
        year = Column(Integer)

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
        name = Column(Text(MAX_USER_NAME_LEN), index=True, unique=True)
        pwdAuthToken = Column(Text)
        mfa = Column(LargeBinary, default=b"*")
        fidoPub = Column(LargeBinary, default=b"*")
        fidoID = Column(LargeBinary, default=b"*")
        fidoChallenge = Column(LargeBinary, default=b"*")
    
    class PubKeyTable(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        Uid: int
        key: str
        krVersion: str"""

        __tablename__ = "pubKeys"
        id = Column(Integer, primary_key=True)
        Uid = Column(Integer, ForeignKey(f"{USER_TABLE_NAME}.id"), index=True,)
        krVersion = Column(Text, default=__version__)
        key = Column(LargeBinary)

    class SessionKeys(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        id: int
        Uid: int
        key: str
        exp: DateTime
        iss: DateTime"""

        __tablename__ = "sessions"
        id = Column(Integer, primary_key=True)
        Uid = Column(Integer, ForeignKey(f"{USER_TABLE_NAME}.id"), index=True)
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
        Uid = Column(Integer, ForeignKey(f"{USER_TABLE_NAME}.id") ,index=True)
        name = Column(Text(MAX_USER_NAME_LEN), index=True)
        value = Column(LargeBinary)
        __table_args__ = (Index('_name_Uid_index', 'Uid', 'name'),
                          UniqueConstraint('name', 'Uid', name='uc_name_uid'))

    class UserShareTable(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        sender: int
        name: bytes
        salt: bytes
        value: bytes
        shareUid: int"""

        __tablename__ = "userShareData"
        id = Column(Integer, primary_key=True)
        sender = Column(Integer, ForeignKey(f"{USER_TABLE_NAME}.id"), index=True)
        name = Column(Text(MAX_USER_NAME_LEN), index=True)
        value = Column(LargeBinary)
        shareUid = Column(Integer, ForeignKey(f"{USER_TABLE_NAME}.id"), index=True)
        __table_args__ = (
            Index('_name_suid_index', 'sender', 'name', 'shareUid'),
            UniqueConstraint('sender', 'name', 'shareUid', name='uc_sender_name_suid'))

    class UnsafeShare(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        sender: int
        name: string
        value: bytes"""

        __tablename__ = "unsafeShare"
        id = Column(Integer, primary_key=True)
        sender = Column(Integer, ForeignKey(f"{USER_TABLE_NAME}.id"), index=True)
        name = Column(Text(MAX_USER_NAME_LEN), index=True, unique=True)
        value = Column(LargeBinary)

    class PWDReset(Base):  # pylint: disable=too-few-public-methods
        """Database Schema
        Uid: int,
        key: bytes,
        iter: int,
        salt: bytes
        """

        __tablename__ = "pwdReset"
        id = Column(Integer, primary_key=True)
        Uid = Column(Integer, ForeignKey(f"{USER_TABLE_NAME}.id"), index=True)
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
        userId = Column(Integer, ForeignKey(f"{USER_TABLE_NAME}.id"), index=True)


class ConfigTemp:
    """Configuration templates"""

    APP_NAME = "KryptonApp"
    HOST_NAME = ""
    ORIGIN = ""
    # The below options for Argon2 are based on RFC-9106
    # They are higher then the recomended values
    defaultArgonOps = 3
    _memLimitArgon = 268435456
    defaultPasswordResetArgonOps = 4
    defaultCryptoperiod = 2
    defaultSessionPeriod = 15  # Minutes
    defaultLogRetentionPeriod = 43200  # Minutes
    _saltLen = 16
    _totpSecretLen = 20
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
        except Exception:
            error = True
        if test is None or error:
            stmt = DBschemas.CryptoTable(
                id=1,
                ctext=b"Position Reserved",
                salt=b"Position Reserved",
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
        except Exception:
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
