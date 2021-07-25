from PySec import RestDecrypt,RestEncrypt
import os
input("Go")
key = os.urandom(32)
print(RestDecrypt(RestEncrypt(b"Hello",key),key))
