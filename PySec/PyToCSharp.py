import sys
import ctypes
def runner(name):
    read = open("\\\\.\\pipe\\" + name, 'rb', 0)
    read = open(name, 'wb', 0)
