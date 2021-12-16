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
    def hmsCipher(self,key):
        self.key = key
    def hsmDecipher(self):
        return self.key
    def __init__(self, base="defaultBase",tk=Tk(), trust:bool=None, kmsport:bool=None,trustKey:bytes=None)->None:
        key = os.urandom(32)
        self.base = base
        self.root = tk
        if trust == None:
            self.trust = messagebox.askyesno(master=self.root, title="Trust?", message="Do you trust this PC and the Microsoft Account linked to it?")
        else:
            self.trust = trust
        self.keydb = sqlite3.connect(PySec.key)
        self.c = self.keydb.cursor()
        try:
            self.c.execute("SELECT * FROM "+PySec.antiSQLi(self.base))
        except(sqlite3.OperationalError):
            if kmsport == None:
                question = messagebox.askyesno(master=self.root, title="Keys", message="Would you like to import a kms (unsupported)?")
                if question == False:
                    self.c.execute("CREATE TABLE '"+PySec.antiSQLi(self.base)+"' (tbl text, key text)")
                    try:
                        self.c.execute("INSERT INTO keys VALUES (?,?)",(self.base,key))
                    except(sqlite3.OperationalError):
                        self.c.execute("CREATE TABLE keys (base text, key blob)")
                        self.c.execute("INSERT INTO keys VALUES (?,?)",(self.base,key))
                    self.keydb.commit()
                else:
                    pass
            else:
                pass

        self.c.execute("SELECT key FROM keys WHERE db=?",(self.base,))
        key = self.c.fetchone()[0]
        if self.trust:
            self.key = self.hmsCipher(key)
        else:
            if trustKey is None:
                keyr = getKey(self.root)
                messagebox.showinfo(master = self.root,title="Enter Key", message="Select OK once you have entered the PIN")
                self.key = PySec.RestEncrypt(key,keyr.value,True)
            else:
                self.key = PySec.RestEncrypt(key,trustKey,True)

    def pin(self, rebase:bool=False, kc:sqlite3.Connection=None, base:bool=True, trustKey:bytes=None) -> bytes:
        if base:
            base=self.base
        r = self.c.execute("SELECT key FROM keys WHERE db = ?", (self.base,))
        r = self.c.fetchone()
        r = r[0]
        if self.trust and not rebase:
            return RestEncrypt(r,self.hsmDecipher(),True)
        elif self.trust and rebase:
            r = kc.execute("INSERT INTO keys VALUES (?,?)", (base, RestEncrypt(os.urandom(32),getKey(self.root).value,True,True)))
        elif not self.trust and not rebase:
            if trustKey is None:
                key = getKey(self.root)
                messagebox.showinfo(master = self.root,title="Enter Key", message="Select OK once you have entered the PIN")
                key = RestDecrypt(self.key,getKey(self.root).value,False)
            else:
                key = RestDecrypt(trustKey,getKey(self.root).value,False)
            return key
        elif not self.trust and rebase:
            raise ValueError("You cannot not trust and recrypt keys simultaniously!")
        else:
            raise ValueError("Options contain invalid values!")

    def getTableKey(self, table : str) -> bytes:
        self.c.execute("SELECT key FROM "+PySec.antiSQLi(self.base)+ " WHERE tbl = ?",(table,)) 
        r = self.c.fetchone()
        if r == None:
            self.configTable(self, table)
            self.c.execute("SELECT key FROM "+PySec.antiSQLi(self.base)+ " WHERE tbl = ?",(table,)) 
            r = self.c.fetchone()
        self.c.execute()
        r = r[0]
        r = RestDecrypt(r,self.pin(),True)
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
        if pwd == None:
            pwd = getKey(self.root)
            messagebox.showinfo(master=self.root, title="Password", message="Please enter the password needed to import the keys on the other machine.")
            pwd = pwd.value
        kc.execute("CREATE TABLE keys (db text, key text)")
        baseCount=0
        for base in bases:
            kc.execute("INSERT INTO keys VLUES (?, ?)", (base, self.pin(rebase=True, kc=kc)))
            for table in tables[baseCount]:
                key = bk.execute("SELECT key FROM "+PySec.antiSQLi(base[2:])+" WHERE tbl= ?",(table))
                key = RestDecrypt(key,self.pin(rebase=True, kc=kc, base=base),True,True)
                key = RestEncrypt(key,self.pin(rebase=True, kc=kc, base=base),True,True)
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
        self.value=self.e.get()
        self.top.destroy()
        self.value = PySec.getKeyFromPass(self.e.get()) ## This is problamatic.        


class crypto(kms):
    '''
    Ciphers and deciphers strings. Can also store strings securely and supports CRUD operations
    '''
    def __init__(self, baseKMS="{secureStore"):
        super().__init__(base=baseKMS)

    #Ciphers
    def crypt(self,what:bytes) -> bytes:
        rec = analyzeSecurity()
        table = rec.getTableRecommendation()
        data = RestEncrypt(what,self.getTableKey(table),True,True)
        return data

    def decrypt(self,what:bytes)->bytes:
        rec = analyzeSecurity()
        table = rec.getTableRecommendation()
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

