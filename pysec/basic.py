import os
import sqlite3
import tkinter as tk
from . import _cryptoDB, _altKeyDB
from .globals import _restEncrypt, _restDecrypt, zeromem, _getKey

class kms():
    def __secureCipher(self,text, pwd):
        if self._masterHSM:
            pass
        else:
            key = _getKey(pwd)
            r = _restEncrypt(text, key)
            zeromem(key)
            return r
 #Will also need to check the level of HSM: only master key or all keys. 
    def __secureDecipher(self, ctext:str|bytes, pwd:str|bytes):
        if self.hsmEnabled:
            pass
        else:
            key = _getKey(pwd)
            r = _restDecrypt(ctext, _getKey(pwd))
            zeromem(key)
            return r
    
    def __init__(self, keyDB:sqlite3.Connection=_altKeyDB)->None:
        self.keydb = keyDB
        self.c = keyDB.cursor()
    
    def exportKeys(self):
        pass

    def importKeys(self):
        pass

    def getKey(self, name:str, pwd:str|bytes=None) -> bytes:
        self.c.execute("SELECT key FROM keys WHERE name == ?",(name,)) 
        key = self.c.fetchone()[0]
        r = self.__secureDecipher(key, pwd)
        return r

    def createNewKey(self, name:str, pwd:str|bytes=None) -> str:
        self.c.execute("SELECT * FROM keys WHERE name=?",(name,))
        if self.c.fetchone() != None:
            raise ValueError("Such a name already exists")
        k = os.urandom(32)
        k = self.__secureCipher(k, pwd)
        self.c.execute("INSERT INTO keys VALUES (?, ?)", (name, k))
        self.keydb.commit()
        return k
    
    def removeKey(self, name:str, pwd:str|bytes=None) -> None:
        zeromem(self.getKey(name, pwd))
        self.c.execute("DELETE FROM crypto WHERE name=?", (name,))
        return

class getKey():
    def __init__(self):
        self.value = ""
        self.root=tk.Toplevel()
        self.l=tk.Label(self.root,text="Please enter the password for database key managment:")
        self.l.pack()
        self.e=tk.Entry(self.root)
        self.e.pack()
        self.b=tk.Button(self.root,text='Ok',command=self.cleanup)
        self.b.pack()
    def cleanup(self):
        self.value = self.e.get()
        self.root.destroy()

class crypto(kms):
    '''
    Ciphers and deciphers strings. Can also store strings securely and supports CRUD operations
    '''
    def __init__(self, keyDB:sqlite3.Connection = _cryptoDB):
        self.keydb = keyDB
        self.c = self.keydb.cursor()
        id = int(self.c.execute("SELECT MAX(id) FROM crypto").fetchone()[0])
        if id == None:
            self.id=1
        else:
            self.id = id
        super().__init__(self.keydb)
    
    def exportData(self):
        pass

    def importData(self):
        pass
    
    def crypt(self,data:bytes|str, pwd:str|bytes=None) -> bytes:
        id = self.id
        self.id+=1
        key = self.createNewKey(str(id), pwd)
        self.c.execute("INSERT INTO crypto VALUES (?, ?)",(id,_restEncrypt(data,key)))
        zeromem(key)
        return id

    def decrypt(self, data:bytes, pwd:str|bytes=None)->bytes:
        key = self.getKey(str(int),pwd)
        text = _restDecrypt(data,key)
        zeromem(key)
        return text

    def secureCreate(self,what:bytes, pwd=None):
        id = self.id
        self.id+=1
        key = self.createNewKey(str(id), pwd)
        self.c.execute("INSERT INTO crypto VALUES (?, ?)",(id,_restEncrypt(what)))
        zeromem(key)
        self.keydb.commit()
        return id
    
    def secureRead(self, id:int, pwd:str|bytes):
        self.c.execute("SELECT ctext FROM crypto WHERE id=?", (id,))
        ctext = self.c.fetchone()[0]
        if ctext == None:
            raise ValueError("Your selected data does not exists")
        key = self.getKey(str(id),pwd)
        text = _restDecrypt(ctext,key)
        zeromem(key)
        return text
    
    def secureUpdate(self, id:int, new:str|bytes, pwd:str|bytes):
        zeromem(self.secureRead(id,pwd))
        key = self.getKey(str(id),pwd)
        ctext = _restEncrypt(new, key)
        zeromem(key)
        self.c.execute("UPDATE crypto SET ctext=? WHERE id=?", (ctext, id))
        self.keydb.commit()
        return
    
    def secureDelete(self,id:int, pwd:str|bytes=None) -> None:
        zeromem(self.secureRead(id,pwd))
        self.c.execute("DELETE FROM crypto WHERE id=?",(id,))
        self.removeKey(str(id),pwd)
        self.keydb.commit()
        return
