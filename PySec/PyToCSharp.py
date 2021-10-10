import ctypes
from PySec import RestEncrypt, RestDecrypt, DLL
from PySec import strbuff
import os

input("Go")
count = 0
for i in range(10):
    key = os.urandom(32)
    text = input("Please enter text to crypto! ").encode("utf-8")
    print("Text: ",text)
    print("Result, ",RestDecrypt(RestEncrypt(text,key),key))
