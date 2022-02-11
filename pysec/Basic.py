from typing import Iterable
import hashlib
import sqlite3
from tkinter import messagebox
from tkinter import *
import os
import ctypes
import sys 

from .globals import restEncrypt, restDecrypt, zeromem
from . import globals

# Create a database where the table keys will be imported from the keyfile. 
# It will recognise the database with information from the dbinfo table. It will store the 
# hash of the unique activation code to recognise the name of the localy stored db key.

def isBaseNameAvailable(self,name:bytes)->bool:
    falsey = False
    for table in globals.cursor.excecute("SELECT * FROM SQLite_master"):
        if table[1] == name:
            falsey = True
    if falsey == True:
        return False
    else:
        return True

class kms():
    #Needed: update table keys
    hsmEnabled = False
    def secureCipher(self,text):
        if self.hsmEnabled:
            pass
        else:
            restEncrypt(text,"Just debug")

    def secureDecipher(self,ctext):
        if self.hsmEnabled:
            pass
        else:
            restDecrypt(ctext,"Just debug")

    def importKeys(self):
        pass
    
    def __init__(self)->None:
        self.keydb = globals.keyDB 
        self.c = globals.cursor

    def getKey(self, name : str) -> bytes:
        self.c.execute("SELECT key FROM keys WHERE name = ?",(name,)) 
        key = self.c.fetchone()[0]
        r = self.secureDecipher(key)
        return r

    def createNewKey(self, name:str) -> None:
        k = os.urandom(32)
        k = self.secureCipher(k)
        self.c.execute("INSERT INTO keys VALUES (?, ?)", (name, k))
        self.keydb.commit()
        return None

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
        self.value = globals.getKeyFromPass(self.e.get())  


class crypto(kms):
    '''
    Ciphers and deciphers strings. Can also store strings securely and supports CRUD operations
    '''
    def __init__(self):
        pass
    #Ciphers
    def crypt(self,what:bytes) -> bytes:
        pass

    def decrypt(self,what:bytes)->bytes:
        pass

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

