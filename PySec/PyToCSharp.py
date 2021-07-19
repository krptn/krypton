import sys
import ctypes
import os
from ctypes import c_char_p, cdll
import PySec
input("Go")
a = cdll.LoadLibrary(r"Cross-PlatformCryptoLib\out\build\x64-Debug\Cross-PlatformCryptoLib.dll")
input("Go")

if a.Init() ==0:
    print("Error")
Encrypt = a.CAESEncrypt
Encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, c_char_p]
Encrypt.restype = ctypes.c_char_p
input("Go")

b = os.urandom(32)
print('Key ', b)
strbuff = ctypes.create_string_buffer
text = b"fgf"
print("Text: ",text)
buff = strbuff(text)
iv = ctypes.create_string_buffer(16)
kbuff=strbuff(b)
result = Encrypt(buff, kbuff, iv)
print('Result ', result)
print("IV: ", iv.value)


input('Go Decrypt')
cbuff = strbuff(result)
kbuff=strbuff(b)
Decrypt = a.CAESDecrypt
Decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
Decrypt.restype = ctypes.c_char_p
result = Decrypt(iv,kbuff,cbuff)
print("Decrypted: ",result)

