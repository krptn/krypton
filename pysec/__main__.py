import pysec
import os

try:
    os.remove("PySec.key")
except:
    pass
pysec.kms.createNewKey(name="example")
print(pysec.kms.getKey("example"))
