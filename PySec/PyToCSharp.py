from PySec import RestEncrypt, RestDecrypt, a
import os
input("Go")

key = os.urandom(32)
text = b"Hello!"
print("Text: ",text)
print("Result, ",RestDecrypt(RestEncrypt(text,key),key))

test = a.test
test.restype = int

def tester(ctext:bytes,key:bytes)->int:
    s=test(ctext,key)
    return s
for i in range(11):
    print(tester(os.urandom(32),b"Hello"))