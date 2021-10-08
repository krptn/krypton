import ctypes
from PySec import RestEncrypt, RestDecrypt, a
from PySec import strbuff
import os
input("Go")

key = os.urandom(32)
text = b"Hello!"
print("Text: ",text)
print("Result, ",RestDecrypt(RestEncrypt(text,key),key))

test = a.test
test.restype = int
test.argtypes = [ctypes.c_char_p,ctypes.POINTER(ctypes.c_char)]
def tester(ctext:bytes,key:bytes)->int:
    s=test(ctext,key)
    return s


for i in range(11):
    print(tester(b"Hello",os.urandom(32)))

