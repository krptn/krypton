from PySec.Basic import crypto
import PySec
from functools import wraps
import os

"Decoraters to pull functions into safety/security"
def AddSec(deco):
    def security(self):
        deco = self.deco
        self = self
        def lock():
            for a in dir(deco):
                if a in PySec.ignore:
                    pass
                else:
                    b=self.crypt.crypt(getattr(deco,a))
                    setattr(deco, a, b)
                    del b
        def set1value(value,x):
            setattr(deco,value,self.crypt.crypt(x))
        def get1value(value):
            return self.crypt.decrypt(getattr(deco,value))
        def unlock():
            for a in dir(deco):
                if a.startswith("_"):
                    pass
                else:
                    b = self.crypt.decrypt(getattr(deco,a))
                    setattr(deco, a, b)
                    del b
    
    a = deco()
    a.security = security
    a.security.base = "tempy"
    a.security.crypt = crypto(baseKMS=a.security.base)
    a.security().lock()
    return a

    

