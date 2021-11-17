setup = """"""
from PySec import AESEncrypt, AESDecrypt
import os
import timeit
run = """ """
text = b"Its aim is to test the performance of the crypto."
key = os.urandom(32)
ctext = AESEncrypt(text,key)
a=AESDecrypt(ctext,key)
print(a)

#print(timeit.timeit(setup = setup,stmt = run, number = 100000000000))
