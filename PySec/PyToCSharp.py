import sys
import ctypes
def runner(name):
    read = open("\\\\.\\pipe\\" + name, 'rb', 0)
    write = open(name, 'wb', 0)


class activateCSharp():
    def __init__(self, pipe):
        self.read = open('\\\\.\\pipe\\'+pipe, 'rb', 0)
        self.write = open('\\\\.\\pipe\\'+pipe, 'wb', 0)
    def getcrypto(self):
        pass