import ctypes
from multiprocessing import connection
import sqlite3
import sys
import os
data_path = ""
key = "PySec.key"
key_path = data_path+key
Adrr = id

from CryptoLib import AESEncrypt, AESDecrypt
import CryptoLib
CryptoLib.init()

__keyDB:sqlite3.Connection = sqlite3.connect(key_path)
__cursor = __keyDB.cursor()

_restEncrypt = AESEncrypt
_restDecrypt = AESDecrypt

def getEncryptor():
    return _restEncrypt

def getDecryptor():
    return _restDecrypt

class StrBuilder():
    def __init__(self,lenNum : int):
        self.len = lenNum
        self.used = 0
        self.data = ctypes.create_string_buffer(lenNum)
    def StringAdd(self, data : bytes, lenNum:int=-1) -> None:
        if lenNum == -1:
            lenNum = self.used
        if self.len >= (len(data)+lenNum):
            a = bytearray(data)
            self.data[lenNum:len(data)] = a
            self.used+=lenNum
            zeromem(a)
        else:
            raise ValueError("Data is longer than buffer size.")
    StrValue = lambda self: self.data.value
    def Clear(self) -> None:
        ctypes.memset(self.data,0,self.len)
    def __del__(self):
        self.Clear()

def zeromem(obj:str)->None: #C-Style function to clear the content of str and bytes
    ctypes.memset(id(obj)+(sys.getsizeof(obj)-len(obj)),0,len(obj))

def antiSQLi(name:bytes, info:bool=True)->str:
    #Santizes and de-santizes inputs before constructing sql cmds to avoid injections
    if info:
        a = StrBuilder(len(name)*4+3)
        a.StringAdd(b'"')
        for ch in name:
            a.StringAdd((str(ord(ch))+"/").encode("utf-8"))
        result = a.StrValue()[:-1].decode("utf-8")
        result+='"'
        a.Clear()
    elif not info:
        a = StrBuilder(len(name))
        a.StringAdd(b'"')
        nameb = name[1:]
        zeromem(name)
        name=nameb[:-1]
        zeromem(nameb)
        t = name.split(b"/")
        for i in t:
            a.StringAdd(chr(int(i)))
        result = a.StrValue.decode("utf-8")
        a.Clear()
    else:
        raise TypeError("Must be type str or type int")
    return result

try:
    __cursor.execute("SELECT * FROM keys")
except(sqlite3.OperationalError):
    __cursor.execute("CREATE TABLE keys (name text, key blob)")
    __keyDB.commit()

keyDB2 = sqlite3.connect("crypto.db")
c = keyDB2.cursor()
try:
    c.execute("SELECT * FROM keys")
except(sqlite3.OperationalError):
    c.execute("CREATE TABLE keys (name text, key blob)")
    keyDB2.commit()
try:
    c.execute("SELECT * FROM crypto")
except(sqlite3.OperationalError):
    c.execute("CREATE TABLE crypto (id int, ctext blob)")
    keyDB2.commit()
c.close()
keyDB2.close()
del c
del __keyDB