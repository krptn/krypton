import sqlite3
import hashlib
import os
import PySec

def setup():
    try:
        os.remove(PySec.key)
    except:
        pass
    conn = sqlite3.connect(PySec.key)
    c = conn.cursor()
    c.execute("CREATE TABLE keys (db text, key blob)")
    code = hashlib.sha256(PySec.getUser()).digest()
    c.execute("CREATE TABLE dbinfo (user text, identifiy text)")
    c.execute("INSERT INTO dbinfo VALUES (? , ?)", (code, code))
    PySec.Basic.antiExploit.zeromem(code)
    conn.commit()
    conn.close()

setup()

