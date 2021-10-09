import ctypes
from PySec import RestEncrypt, RestDecrypt, DLL
from PySec import strbuff
import os

input("Go")
count = 0
while True:
    count += 1
    try:
        key = os.urandom(32)
        text = input("Please enter text to crypto! ").encode("utf-8")
        print("Text: ",text)
        print("Result, ",RestDecrypt(RestEncrypt(text,key),key))

        test = DLL.test
        test.restype = int
        test.argtypes = [ctypes.c_char_p,ctypes.POINTER(ctypes.c_char)]
        def tester(ctext:bytes,key:bytes)->int:
            s=test(ctext,key)
            return s
        a = input("Please enter text to crypt: ").encode("utf-8")
        print(tester(a,os.urandom(32)))
        if count == 10:
            break
    except:
        b = input("Error occured. Press enter quit to quit and re to retry: ")
        if b == "re":
            continue
        else:
            break
