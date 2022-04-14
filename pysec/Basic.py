import os
import sqlite3
import tkinter as tk
from . import globals
from . import cryptoDBLocation
from .globals import _restEncrypt, _restDecrypt, zeromem
import pysec

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
    def __secureCipher(self,text, pwd):
        if self._masterHSM:
            pass
        else:
            return _restEncrypt(text,pwd)
 #Will also need to check the level of HSM: only master key or all keys. 
    def __secureDecipher(self,ctext, pwd):
        if self.hsmEnabled:
            pass
        else:
            return _restDecrypt(ctext,pwd)

    def importKeys(self):
        pass
    
    def __init__(self, keyDB:sqlite3.Connection, master:bool=False, all:bool=False)->None:
        self.keydb = keyDB
        self._masterHSM = master
        self._allHDM = all
        self.c = keyDB.cursor()

    def getKey(self, name : str, pwd:str=None) -> bytes:
        self.c.execute("SELECT key FROM keys WHERE name == ?",(name,)) 
        key = self.c.fetchone()[0]
        r = self.__secureDecipher(key, pwd)
        return r

    def createNewKey(self, name:str, pwd:str=None) -> str:
        self.c.execute("SELECT * FROM keys WHERE name=?",(name,))
        if self.c.fetchone() != None:
            raise ValueError("Such a name already exists")
        k = os.urandom(32)
        k = self.__secureCipher(k, pwd)
        self.c.execute("INSERT INTO keys VALUES (?, ?)", (name, k))
        self.keydb.commit()
        return k
    
    def exportKeys():
        pass

class getKey():
    def __init__(self):
        self.value = " "
        self.root=tk.Tk()
        self.l=tk.Label(self.root,text="Please enter the password for database key managment:")
        self.l.pack()
        self.e=tk.Entry(self.root)
        self.e.pack()
        self.b=tk.Button(self.root,text='Ok',command=self.cleanup)
        self.b.pack()
    def cleanup(self):
        self.root.destroy()
        self.value = globals.getKeyFromPass(self.e.get())  


class crypto(kms):
    '''
    Ciphers and deciphers strings. Can also store strings securely and supports CRUD operations
    '''
    def __init__(self):
        self.keydb = sqlite3.connect(cryptoDBLocation)
        self.c = self.keydb.cursor()
        id = int(self.c.execute("SELECT MAX(id) FROM crypto").fetchone()[0])
        if id == None:
            self.id=1
        else:
            self.id = id
        super().__init__(self.keydb)
    #Ciphers
    def crypt(self,what:bytes, pwd=None) -> bytes:
        id = self.id
        self.id+=1
        key = self.createNewKey(str(id), pwd)
        self.c.execute("INSERT INTO crypto VALUES (?, ?)",(id,_restEncrypt(what)))
        zeromem(key)
        return id

    def decrypt(self,what:bytes)->bytes:
        pass

    #CRUD
    def secureCreate(self,what:bytes, pwd=None):
        d = self.id
        self.id+=1
        key = self.createNewKey(str(id), pwd)
        self.c.execute("INSERT INTO crypto VALUES (?, ?)",(id,_restEncrypt(what)))
        zeromem(key)
        return id
    
    def sercureRead(self,what:bytes):
        pass
    def secureUpdate(self,what:bytes):
        pass
    def sucureDelete(self,what:bytes):
        pass
