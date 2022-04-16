import sqlite3
# Setup DB for crypto class. To be only called once on every db
def setupCryptoDB(path:str) -> None:
  conn = sqlite3.connect(path)
  c = conn.cursor()
  c.execute("CREATE TABLE crypto (id int, ctext blob)")
  c.execute("INSERT INTO crypto VALUES (?, ?)", (0, b"Position Reserved"))
  c.execute("CREATE TABLE keys (name text, key blob)")
  conn.commit()
  c.close()
  conn.close()

# Setup DB for kms class. To be only called once on every db. 
def setupKeyDB(path:str):
  conn = sqlite3.connect("altKMS.db")
  c = conn.cursor()
  c.execute("CREATE TABLE keys (name text, key blob)")
  conn.commit()
  c.close()
  conn.close()