setup = """"""
from PySec import Encrypt, Decrypt
import os
import timeit

run = """ """
text = b"Its aim is to test the performance of the crypto."
key = os.urandom(32)
ctext = Encrypt(text,key)
a=Decrypt(ctext,key)
print(a)

#print(timeit.timeit(setup = setup,stmt = run, number = 100000000000))
