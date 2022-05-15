import sqlite3
import pysec
# Setup DB for crypto class. 
def setupCryptoDB(path:str|sqlite3.Connection) -> None:
  if isinstance(path,str):
    conn = sqlite3.connect(path)
  else:
    conn = path
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
    pysec.__cryptoDBLocation = conn

# Setup DB for kms class. 
def setupKeyDB(path:str|sqlite3.Connection):
  if isinstance(path,str):
    conn = sqlite3.connect(path)
  else:
    conn = path
  c = conn.cursor()
  try:
    c.execute("CREATE TABLE keys (name text, key blob)")
  except:
    pass
  finally:
    conn.commit()
    c.close()
    pysec.__altKeyDB = conn

def setupUserDB(path:str|sqlite3.Connection):
  if isinstance(path,str):
    conn = sqlite3.connect(path)
  else:
    conn = path
  c = conn.cursor()
  try:
    c.execute("CREATE TABLE users (name text, id int)")
    c.execute("CREATE TABLE pubKeys (name text, key blob)")
  except:
    pass
  finally:
    conn.commit()
    c.close()
    conn.close()
  pysec.__userDB = conn
