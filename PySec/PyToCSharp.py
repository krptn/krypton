from PySec import RestEncrypt, RestDecrypt
import os
input("Go")
key = os.urandom(32)
text = b"Hello "
print("Text: ",text)
print("Result, ",RestDecrypt(RestEncrypt(text,key),key))
