import ctypes
from PySec import Encrypt, Decrypt
import os
#I cannot believe this!! The Crypto Works!!

input("Go")
count = 0
text = b"Hello this is a random piece of text to be encrypted and decrypted by the openssl AESGCM interface Its aim is to test the performance of the crypto."
#text = b"Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
for i in range(1):
    key = os.urandom(32)
    ctext = Encrypt(text,key)
    a=Decrypt(ctext,key)
    print(a)
