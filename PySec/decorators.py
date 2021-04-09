from PySec.Basic import crypto
import PySec
from functools import wraps
import os

"Decoraters to pull functions into safety/security"
def AddSec(deco):
    class AddSecurity():
        def __init__(self):
            self.base="tempy"
            self.crypt = crypto(baseKMS=self.base)
            self.lock()
        def lock(self):
            for a in dir(deco):
                if a.startswith("__"):
                    pass
                else:
                    b=self.crypt.crypt(getattr(deco,a))
                    setattr(deco, a, b)
                    del b
        def set1value(self,value,x):
            setattr(deco,value,self.crypt.crypt(x))
        def get1value(self,value):
            return self.crypt.decrypt(getattr(deco,value))
        def unlock(self):
            for a in dir(deco):
                if a.startswith("_"):
                    pass
                else:
                    b = self.crypt.decrypt(getattr(deco,a))
                    setattr(deco, a, b)
                    del b

        def __call__(self, *args, **kwargs):
            self.unlock()
            deco(*args,**kwargs)
            self.lock()

    return AddSecurity()

