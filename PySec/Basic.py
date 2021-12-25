from typing import Iterable
import hashlib
import sqlite3
from tkinter import messagebox
from tkinter import *
import os
import ctypes
import PySec
import sys 
from PySec import AESDecrypt, AESEncrypt, StrBuilder, Adrr
RestDecrypt = AESDecrypt
RestEncrypt = AESEncrypt
# Create a database where the table keys will be imported from the keyfile. 
# It will recognise the database with information from the dbinfo table. It will store the 
# hash of the unique activation code to recognise the name of the localy stored db key.

def isBaseNameAvailable(self,name:bytes)->bool:
    conn = sqlite3.connect(PySec.key)
    c = conn.cursor()
    falsey = False
    for table in self.c.excecute("SELECT * FROM SQLite_master"):
        if table[1] == name:
            falsey = True
    if falsey == True:
        return False
    else:
        return True

class kms():
    #Needed: update table keys
    def secureCipher(self,text,pwdFromUser):
        pass

    def secureDecipher(self,ctext,pwdFromUser):
        pass

    def firstUse(self): #For bases only
        pass
    def importKeys(self):
        pass

    def loadFromConfig(self):
        pass

    def createBase(self):
        self.c.execute("CREATE TABLE '"+PySec.antiSQLi(self.base)+"' (tbl text, key text)")
        self.keydb.commit()


    def __init__(self, base="defaultBase")->None:
        self.base = base
        self.keydb = sqlite3.connect(PySec.key)
        self.c = self.keydb.cursor()
        try:
            self.c.execute("SELECT * FROM "+PySec.antiSQLi(base)) # see if db is set up
        except(sqlite3.OperationalError):
            self.firstUse()

        self.c.execute("SELECT key FROM keys WHERE db=?",(self.base,))
        self.Cipheredkey = self.c.fetchone()[0]

    def getTableKey(self, table : str) -> bytes:
        self.c.execute("SELECT key FROM "+PySec.antiSQLi(self.base)+ " WHERE tbl = ?",(table,)) 
        key = self.c.fetchone()[0]
        r = self.secureDecipher(key)
        return r

    def configTable(self,table : (str or bytes)) -> None:
        k = os.urandom(32)
        k = RestEncrypt(k,self.pin(),True,True)
        self.c.execute("INSERT INTO "+PySec.antiSQLi(self.base)+" VALUES (?, ?)", (table, self.key))
        self.keydb.commit()
        return None

    def exportKeys(self, bases : str, tables : bytes, path : bytes, pwd : bytes):

        tmpkeystore = sqlite3.connect(PySec.key)
        tmpksys = sqlite3.connect(path)
        bk = tmpkeystore.cursor() #Old
        kc = tmpksys.cursor() #New

        kc.execute("CREATE TABLE keys (db text, key text)")
        baseCount=0
        for base in bases:
            kc.execute("INSERT INTO keys VLUES (?, ?)", (base, self.pin(rebase=True, kc=kc)))
            for table in tables[baseCount]:
                key = bk.execute("SELECT key FROM "+PySec.antiSQLi(base[2:])+" WHERE tbl= ?",(table))
                key = self.secureDecipher(key,True)
                key = self.secureCipher(key,True)
                kc.execute("INSERT INTO "+PySec.antiSQLi(base)+" VALUES (?, ?)",(table,key))
                tmpksys.commit()
            baseCount+=1
        tmpkeystore.close()
        tmpksys.close()

class getKey():
    def __init__(self,master):
        self.value = " "
        top=self.top=Toplevel(master)
        self.l=Label(top,text="Please enter the password for database key managment:")
        self.l.pack()
        self.e=Entry(top)
        self.e.pack()
        self.b=Button(top,text='Ok',command=self.cleanup)
        self.b.pack()
    def cleanup(self):
        self.top.destroy()
        self.value = PySec.getKeyFromPass(self.e.get())  


class crypto(kms):
    '''
    Ciphers and deciphers strings. Can also store strings securely and supports CRUD operations
    '''
    def __init__(self, baseKMS="{secureStore"):
        super().__init__(base=baseKMS)
        self.rec = analyzeSecurity)Ö

    #Ciphers
    def crypt(self,what:bytes) -> bytes:
        table = self.rec.getTableRecommendation()
        data = RestEncrypt(what,self.getTableKey(table),True,True)
        return data

    def decrypt(self,what:bytes)->bytes:
        table = self.rec.getTableRecommendation()
        data = RestDecrypt(what,self.getTableKey(table),True,True)
        return data

    #CRUD
    def secureCreate(self,what:bytes):
        pass
    def sercureRead(self,what:bytes):
        pass
    def secureUpdate(self,what:bytes):
        pass
    def sucureDelete(self,what:bytes):
        pass

class analyzeSecurity():
    #This will analyze the security of the current installation - collect logs and other things
    def __init__(self):
        pass
    def getTableRecommendation(self) -> str:
        return "Example - do not trust"

