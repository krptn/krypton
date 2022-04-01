import os
import sqlite3
import tkinter as tk
from .globals import restEncrypt, restDecrypt, zeromem
from . import globals
import pysec

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
    hsmEnabled = False
    def secureCipher(self,text, pwd):
        if self.hsmEnabled:
            pass
        else:
            return restEncrypt(text,pwd)
 #Will also need to check the level of HSM: only master key or all keys. 
    def secureDecipher(self,ctext, pwd):
        if self.hsmEnabled:
            pass
        else:
            return restDecrypt(ctext,pwd)

    def importKeys(self):
        pass
    
    def __init__(self, keyDB:sqlite3.Connection=globals.keyDB)->None:
        self.keydb = keyDB
        self.c = keyDB.cursor()

    def getKey(self, name : str, pwd:str=None) -> bytes:
        self.c.execute("SELECT key FROM keys WHERE name == ?",(name,)) 
        key = self.c.fetchone()[0]
        r = self.secureDecipher(key, pwd)
        return r

    def createNewKey(self, name:str, pwd:str=None) -> str:
        self.c.execute("SELECT * FROM keys WHERE name=?",(name,))
        if self.c.fetchone() != None:
            raise ValueError("Such a name already exists")
        k = os.urandom(32)
        k = self.secureCipher(k, pwd)
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
        self.keydb = sqlite3.connect("crypto.db")
        self.c = self.keydb.cursor()
        id = int(self.Gc.execute("SELECT MAX(id) FROM crypto").fetchone()[0])
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
        self.c.execute("INSERT INTO crypto VALUES (?, ?)",(id,restEncrypt(what)))
        zeromem(key)
        return id

    def decrypt(self,what:bytes)->bytes:
        pass

    #CRUD
    def secureCreate(self,what:bytes, pwd=None):
        d = self.id
        self.id+=1
        key = self.createNewKey(str(id), pwd)
        self.c.execute("INSERT INTO crypto VALUES (?, ?)",(id,restEncrypt(what)))
        zeromem(key)
        return id
    
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

