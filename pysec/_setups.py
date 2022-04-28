import sqlite3
import pysec
# Setup DB for crypto class. 
def setupCryptoDB(path:str) -> None:
  conn = sqlite3.connect(path)
  c = conn.cursor()
  try:
    c.execute("CREATE TABLE crypto (id int, ctext blob)")
    c.execute("INSERT INTO crypto VALUES (?, ?)", (0, b"Position Reserved"))
    c.execute("CREATE TABLE keys (name text, key blob)")
  except:
    pass
  finally:
    conn.commit()
    c.close()
    conn.close()
    pysec._cryptoDBLocation = sqlite3.connect(path)

# Setup DB for kms class. 
def setupKeyDB(path:str):
  conn = sqlite3.connect(path)
  c = conn.cursor()
  try:
    c.execute("CREATE TABLE keys (name text, key blob)")
  except:
    pass
  finally:
    conn.commit()
    c.close()
    conn.close()
    pysec._altKeyDB = sqlite3.connect(path)

def setupUserDB(path:str):
  conn = sqlite3.connect(path)
  c = conn.cursor()
  try:
    c.execute("CREATE TABLE users (name text, id int)")
    c.execute("CREATE TABLE keys (name text, key blob)")
  except:
    pass
  finally:
    conn.commit()
    c.close()
    conn.close()
  pysec._userDB = sqlite3.connect(path)

