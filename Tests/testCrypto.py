from PySec.Basic import kms
import os
try:
    os.remove("PySec.key")
except:
    pass

k = kms()
k.configTable("example")
print(k.getTableKey("example"))