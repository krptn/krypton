from PySec.Basic import *
import PySec
import os
class VaultObject(crypto):
    def __init__(self, cls):
        self.workingCase = cls
        falsey=False
        self.base="tempy"
        super().__init__(baseKMS=self.base)
    def update(self):
        for a in dir(self.workingCase):
            if a.startswith("__"):
                pass
            else:
                #This will encrypt here 