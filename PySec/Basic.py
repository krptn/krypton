import hashlib
import sqlite3
import pyaes 
from tkinter import messagebox
from tkinter import *
import clr
import os
# Create a database where the table keys will be imported from the keyfile. 
# It will recognise the database with information from the dbinfo table. It will store the 
# hash of the unique activation code to recognise the name of the localy stored db key.

def antiSQLi(name, info=True):
    #Santizes and de-santizes inputs before constructing sql cmds to avoid injections
    result = '''"'''

    if info is True:
        for ch in name:
            result+=str(ord(ch))
            result+="/"
        result = result[:-1]
        result+='''"'''
    elif info is False:
        name = name[1:]
        name=name[:-1]
        t = name.split("/")
        for i in t:
            result+=chr(int(i))
    else:
        raise TypeError("Must be type str or type int")
    return result


class kms():
    #Needed: update table keys
    def hmsCipher(self,key):
        self.key = key
    def hsmDecipher(self):
        return self.key
    def __init__(self, base="defaultBase",tk=Tk(), trust=None, kmsport=None,kmsPath=None, trustKey=None):
        key = os.urandom(32)
        self.base = base
        self.root = tk
        if trust == None:
            self.trust = messagebox.askyesno(master=self.root, title="Trust?", message="Do you trust this PC and the Microsoft Account linked to it?")
        else:
            self.trust = trust
        self.keydb = sqlite3.connect("keystore.db")
        self.c = self.keydb.cursor()
        try:
            self.c.execute("SELECT * FROM "+antiSQLi(self.base))
        except(sqlite3.OperationalError):
            if kmsport == None:
                question = messagebox.askyesno(master=self.root, title="Keys", message="Would you like to import a kms (unsupported)?")
            elif question == True or (kmsport != False and kmsport != None):
                pass #Still needs to be programmed
            else:
                self.c.execute("CREATE TABLE "+antiSQLi(self.base)+" (tbl text, key text)")
                self.c.execute("INSERT INTO keys VALUES (?,?)",(self.base,key))
                self.keydb.commit()
        self.c.execute("SELECT key FROM keys WHERE db=?",(self.base,))
        key = self.c.fetchone()[0]
        if self.trust:
            self.hmsCipher(key)
        else:
            if trustKey is None:
                key = getKey(self.root)
                messagebox.showinfo(master = self.root,title="Enter Key", message="Select OK once you have entered the PIN")
                aes = pyaes.AESModeOfOperationCTR(key.value)
            else:
                aes = pyaes.AESModeOfOperationCTR(trustKey)
            self.key = aes.encrypt(key)
            del aes
        del key

    def pin(self, rebase=False, kc=None, base=True, trustKey=None):
        if base:
            base=self.base
        r = self.c.execute("SELECT key FROM keys WHERE db = ?", (self.base,))
        r = self.c.fetchone()
        r = r[0]
        if self.trust and not rebase:
            aes = pyaes.AESModeOfOperationCTR(self.hsmDecipher())
            return aes.decrypt(r) #None
        elif self.trust and rebase:
            rekey = os.urandom(32)
            aes = pyaes.AESModeOfOperationCTR(pwd)
            r = kc.execute("INSERT INTO keys VALUES (?,?)", (base, aes.encrypt(rekey)))
        elif not self.trust and not rebase:
            if trustKey is None:
                key = getKey(self.root)
                messagebox.showinfo(master = self.root,title="Enter Key", message="Select OK once you have entered the PIN")
                aes = pyaes.AESModeOfOperationCTR(key.value)
            else:
                aes = pyaes.AESModeOfOperationCTR(trustKey)
            key = aes.decrypt(self.key)
            del aes
            return key
            del key 
        elif not self.trust and rebase:
            raise ValueError("You cannot not trust and recrypt keys simultaniously!")
        else:
            raise ValueError("Options contain invalid values!")

    def getTableKey(self, table):
        self.c.execute("SELECT key FROM "+antiSQLi(self.base)+ " WHERE tbl = ?",(table,)) 
        r = self.c.fetchone()
        if r == None:
            self.configTable(self, table)
            self.c.execute("SELECT key FROM "+antiSQLi(self.base)+ " WHERE tbl = ?",(table,)) 
            r = self.c.fetchone()
        r = r[0]
        aes = pyaes.AESModeOfOperationCTR(self.pin()) 
        r = aes.decrypt(r)
        del aes
        return r

    def configTable(self,table):
        k = os.urandom(32)
        aes = pyaes.AESModeOfOperationCTR(self.pin())
        k = aes.encrypt(k)
        del aes
        self.c.execute("INSERT INTO "+antiSQLi(self.base)+" VALUES (?, ?)", (table, self.key))
        self.keydb.commit()
        del table
        del k
        return True


    def exportKeys(self, bases, tables, path, pwd=None):
        tmpkeystore = sqlite3.connect("keystore.db")
        tmpksys = sqlite3.connect(path)
        bk = tempkeystore.cursor() #Old
        kc = tmpksys.cursor() #New
        if pwd == None:
            pwd = getKey(tk.self.root)
            messagebox.showinfo(master=tk.self.root, title="Password", message="Please enter the password needed to import the keys on the other machine.")
            pwd = pwd.value
        kc.execute("CREATE TABLE keys (db text, key text)")
        baseCount=0
        for base in bases:
            kc.execute("INSERT INTO keys VLUES (?, ?)", (base, self.pin(rebase=True, kc=kc)))
            for table in tables[baseCount]:
                key = bk.execute("SELECT key FROM "+antiSQLi(base[2:])+" WHERE tbl= ?",(table))
                aes = pyaes.AESModeOfOperationCTR(self.pin(rebase=True, kc=kc, base=base))
                key = aes.decrypt(key)
                del aes
                aes2 = pyaes.AESModeOfOperationCTR(self.pin(rebase=True, kc=kc, base=base))
                key = aes2.encrypt(key)
                del aes2
                kc.execute("INSERT INTO "+antiSQLi(base)+" VALUES (?, ?)",(table,key))
                del key
                tmpksys.commit()
            baseCount+=1
        del baseCount
        tmpkeystore.close()
        del tmpkeystore
        tmpksys.close()
        del tmpksys
        del pwd
        del kc
        del bc




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
        self.value = hashlib.sha256(self.value.encode('utf-8')).digest()
        del self.e
        del self.l
        del self.b
        del self.top


class crypto(kms):
    '''
    Ciphers and deciphers strings. Can also store strings securely and supports CRUD operations
    '''
    def __init__(self, baseKMS="/&@{;:}°°%*>~/]]^^s$+!/%=((()))))))secureStore;--"):
        super().__init__(base=baseKMS)

    #Ciphers
    def crypt(what):
        rec = analyzeSecurity()
        table = rec.getTableRecommendation()
        del rec
        aes = pyaes.AESModeOfOperationCTR(self.getTableKey(table))
        del table
        data = aes.encrypt(what)
        del aes
        return data

    def decrypt(what):
        rec = analyzeSecurity()
        table = rec.getTableRecommendation()
        del rec
        aes = pyaes.AESModeOfOperationCTR(self.getTableKey(table))
        del table
        data = aes.decrypt()
        del aes
        return data

    #CRUD
    def secureCreate(what):
        pass
    def sercureRead(what):
        pass
    def secureUpdate(what):
        pass
    def sucureDelete(what):
        pass

class analyzeSecurity():
    #This will analyze the security of the current installation - collect logs and other things
    def __init__():
        pass
    def getTableRecommendation():
        return "Example - do not trust"