from PySec import RestDecrypt,RestEncrypt
import os
input("Go")
key = os.urandom(32)
text = b"Hello!"
print("Text: ",text)
print(RestDecrypt(RestEncrypt(text,key),key))
