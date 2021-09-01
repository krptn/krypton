from PySec import RestEncrypt, RestDecrypt, a
import os
input("Go")
"""
key = os.urandom(32)
text = b"Hello!"
print("Text: ",text)
print("Result, ",RestDecrypt(RestEncrypt(text,key),key))
"""
test = a.test
test.restype = int

print(test())