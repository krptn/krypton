import ctypes
from PySec import Encrypt, Decrypt
import os

input("Go")
count = 0
text = b"Its aim is to test the performance of the crypto."
key = os.urandom(32)
#text = b"Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
for i in range(10):
    print("Text:",text)
    ctext = Encrypt(text,key)
    print("Ctext:",ctext)
    a=Decrypt(ctext,key)
    print(a)
