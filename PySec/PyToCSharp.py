from PySec import RestDecrypt,RestEncrypt
import os
input("Go")
key = os.urandom(32)
print(RestDecrypt(RestEncrypt(b"Hello a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a aa a a a a a a a a a a a a a a a a a a aaa a a    aaa!!",key),key))
