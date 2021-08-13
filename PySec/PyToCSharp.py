from PySec import Encrypt, Decrypt
import os
input("Go")
key = os.urandom(32)
text = b"Hello!"
print("Text: ",text)
print(Decrypt(Encrypt(text,key, True),key,True))
