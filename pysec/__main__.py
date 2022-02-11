import pysec
import os

try:
    os.remove("PySec.key")
except:
    pass

kms = pysec.Basic.kms()
kms.createNewKey("example")
print(kms.getKey("example"))
