import sqlite3
import activateProduct
import hashlib
import os


def setup():
    try:
        os.remove("keystore.db")
    except:
        pass
    conn = sqlite3.connect("keystore.db")
    c = conn.cursor()
    c.execute("CREATE TABLE keys (db text, key text)")
    code = hashlib.sha256(activateProduct.getUserIdnetifier()).digest()
    c.execute("CREATE TABLE dbinfo (user text, identifiy text)")
    c.execute("INSERT INTO dbinfo VALUES (? , ?)", (code, code))
    del code
    conn.commit()
    conn.close()
    del c
    del conn


