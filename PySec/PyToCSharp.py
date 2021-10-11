import ctypes
from PySec import Encrypt, Decrypt
import os

input("Go")
count = 0
for i in range(10):
    key = os.urandom(32)
    print("-"*20)
    print("")
    print("Key is:",key)
    text = input("Please enter text to crypto! ").encode("utf-8")
    print("Text: ",text)
    ctext = Encrypt(text,key)
    print("Cipher Text:",ctext)
    print("Key:",key)
    print("Result: ",Decrypt(ctext,key))
